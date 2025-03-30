import boto3
import time
from django.http import JsonResponse, HttpResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.models import User
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework import status
from rest_framework.views import APIView
from botocore.exceptions import ClientError
from .models import VPC

ec2 = boto3.client('ec2')


def create_vpc(cidr_block, subnet_cidr_blocks, availability_zones, vpc_name):
    try:
        response = ec2.create_vpc(
            CidrBlock=cidr_block,
            TagSpecifications=[{
                'ResourceType': 'vpc',
                'Tags': [{'Key': 'Name', 'Value': vpc_name}]
            }]
        )
        vpc_id = response['Vpc']['VpcId']
        print("Created VPC with ID:", vpc_id)

        for subnet_cidr, az in zip(subnet_cidr_blocks, availability_zones):
            subnet_response = ec2.create_subnet(VpcId=vpc_id, CidrBlock=subnet_cidr, AvailabilityZone=az)
            print("Created Subnet:", subnet_response['Subnet']['SubnetId'])

        igw_response = ec2.create_internet_gateway()
        igw_id = igw_response['InternetGateway']['InternetGatewayId']
        print("Created Internet Gateway:", igw_id)

        ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
        print("Attached IGW to VPC")

        route_table_response = ec2.create_route_table(VpcId=vpc_id)
        route_table_id = route_table_response['RouteTable']['RouteTableId']
        ec2.create_route(RouteTableId=route_table_id, DestinationCidrBlock='0.0.0.0/0', GatewayId=igw_id)
        print("Created route table and route")

        subnets = ec2.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])['Subnets']
        if subnets:
            ec2.associate_route_table(RouteTableId=route_table_id, SubnetId=subnets[0]['SubnetId'])
            print("Associated route table with subnet:", subnets[0]['SubnetId'])

        return vpc_id

    except ClientError as e:
        print("Error creating VPC:", e)
        return f"Error creating VPC: {e}"


class WrappedAPIView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        cidr_block = request.data.get('vpc_cidr')
        subnet_cidr_blocks = request.data.get('subnet_cidrs', "").split(',')
        availability_zones = request.data.get('availability_zones', "").split(',')
        vpc_name = request.data.get('vpc_name')

        if not all([cidr_block, subnet_cidr_blocks, availability_zones, vpc_name]):
            return Response({'error': 'Missing required fields'}, status=status.HTTP_400_BAD_REQUEST)

        vpc_id = create_vpc(cidr_block, subnet_cidr_blocks, availability_zones, vpc_name)
        VPC.objects.create(user=request.user, vpc_id=vpc_id, vpc_name=vpc_name)
        print("Stored VPC in database:", vpc_id)

        return Response({'vpc_id': vpc_id}, status=status.HTTP_201_CREATED)


@api_view(['POST'])
def generate_token(request):
    username = request.data.get('username')
    password = request.data.get('password')

    if not username or not password:
        return Response({'error': 'Missing username or password'}, status=status.HTTP_400_BAD_REQUEST)

    user = User.objects.filter(username=username).first()
    if not user or not user.check_password(password):
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

    token, _ = Token.objects.get_or_create(user=user)
    return Response({'token': token.key})


def delete_vpc(request, vpc_id):
    """
    Deletes a VPC along with its dependencies.
    Attempts to remove all components (instances, subnets, IGWs, NAT Gateways,
    route tables, VPC endpoints, network ACLs, peering connections, network interfaces).
    Uses a finite retry loop for VPC deletion to prevent hanging.
    """
    print("delete_vpc called with vpc_id:", vpc_id)
    if request.method == 'POST' and request.headers.get('x-requested-with') == 'XMLHttpRequest':
        print("AJAX request confirmed")
        vpc = get_object_or_404(VPC, vpc_id=vpc_id)
        try:
            # Terminate instances in the VPC
            instances = ec2.describe_instances(
                Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
            )['Reservations']
            instance_ids = [inst['InstanceId'] for res in instances for inst in res['Instances']]
            if instance_ids:
                print("Terminating instances:", instance_ids)
                ec2.terminate_instances(InstanceIds=instance_ids)
                # Wait up to 120 seconds (Delay 10 sec, 12 attempts)
                ec2.get_waiter('instance_terminated').wait(
                    InstanceIds=instance_ids,
                    WaiterConfig={'Delay': 10, 'MaxAttempts': 12}
                )
                print("Instances terminated")

            # Delete subnets
            subnets = ec2.describe_subnets(
                Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
            )['Subnets']
            for subnet in subnets:
                print("Deleting subnet:", subnet['SubnetId'])
                try:
                    ec2.delete_subnet(SubnetId=subnet['SubnetId'])
                except ClientError as e:
                    print("Error deleting subnet", subnet['SubnetId'], e)

            # Detach and delete Internet Gateways
            igws = ec2.describe_internet_gateways(
                Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc_id]}]
            )['InternetGateways']
            for igw in igws:
                print("Detaching and deleting IGW:", igw['InternetGatewayId'])
                try:
                    ec2.detach_internet_gateway(InternetGatewayId=igw['InternetGatewayId'], VpcId=vpc_id)
                    ec2.delete_internet_gateway(InternetGatewayId=igw['InternetGatewayId'])
                except ClientError as e:
                    print("Error deleting IGW", igw['InternetGatewayId'], e)

            # Delete Security Groups (except default)
            security_groups = ec2.describe_security_groups(
                Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
            )['SecurityGroups']
            for sg in security_groups:
                if sg['GroupName'] != 'default':
                    print("Deleting security group:", sg['GroupId'])
                    try:
                        ec2.delete_security_group(GroupId=sg['GroupId'])
                    except ClientError as e:
                        print("Error deleting security group", sg['GroupId'], e)

            # Delete NAT Gateways
            nat_gateways = ec2.describe_nat_gateways(
                Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
            )['NatGateways']
            for nat in nat_gateways:
                print("Deleting NAT gateway:", nat['NatGatewayId'])
                try:
                    ec2.delete_nat_gateway(NatGatewayId=nat['NatGatewayId'])
                except ClientError as e:
                    print("Error deleting NAT gateway", nat['NatGatewayId'], e)

            # Delete Route Tables (non-main only)
            route_tables = ec2.describe_route_tables(
                Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
            )['RouteTables']
            for rt in route_tables:
                associations = rt.get('Associations', [])
                is_main = any(assoc.get('Main') for assoc in associations)
                if not is_main:
                    print("Deleting route table:", rt['RouteTableId'])
                    try:
                        ec2.delete_route_table(RouteTableId=rt['RouteTableId'])
                    except ClientError as e:
                        print("Error deleting route table", rt['RouteTableId'], e)

            # Delete VPC Endpoints
            endpoints = ec2.describe_vpc_endpoints(
                Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
            )['VpcEndpoints']
            for endpoint in endpoints:
                print("Deleting VPC endpoint:", endpoint['VpcEndpointId'])
                try:
                    ec2.delete_vpc_endpoints(VpcEndpointIds=[endpoint['VpcEndpointId']])
                except ClientError as e:
                    print("Error deleting VPC endpoint", endpoint['VpcEndpointId'], e)

            # Delete Network ACLs (non-default)
            acls = ec2.describe_network_acls(
                Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
            )['NetworkAcls']
            for acl in acls:
                if not acl['IsDefault']:
                    print("Deleting network ACL:", acl['NetworkAclId'])
                    try:
                        ec2.delete_network_acl(NetworkAclId=acl['NetworkAclId'])
                    except ClientError as e:
                        print("Error deleting network ACL", acl['NetworkAclId'], e)

            # Delete VPC Peering Connections
            peerings = ec2.describe_vpc_peering_connections(
                Filters=[{'Name': 'requester-vpc-info.vpc-id', 'Values': [vpc_id]}]
            )['VpcPeeringConnections']
            for peering in peerings:
                print("Deleting VPC peering connection:", peering['VpcPeeringConnectionId'])
                try:
                    ec2.delete_vpc_peering_connection(VpcPeeringConnectionId=peering['VpcPeeringConnectionId'])
                except ClientError as e:
                    print("Error deleting VPC peering connection", peering['VpcPeeringConnectionId'], e)

            # Delete Network Interfaces
            network_interfaces = ec2.describe_network_interfaces(
                Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
            )['NetworkInterfaces']
            for interface in network_interfaces:
                if 'Attachment' in interface:
                    print("Detaching network interface:", interface['NetworkInterfaceId'])
                    try:
                        ec2.detach_network_interface(AttachmentId=interface['Attachment']['AttachmentId'])
                    except ClientError as e:
                        print("Error detaching network interface", interface['NetworkInterfaceId'], e)
                print("Deleting network interface:", interface['NetworkInterfaceId'])
                try:
                    ec2.delete_network_interface(NetworkInterfaceId=interface['NetworkInterfaceId'])
                except ClientError as e:
                    print("Error deleting network interface", interface['NetworkInterfaceId'], e)

            # Retry VPC deletion if there are dependency violations (max 5 attempts)
            retries = 5
            for attempt in range(retries):
                try:
                    print("Attempting to delete VPC:", vpc_id)
                    ec2.delete_vpc(VpcId=vpc_id)
                    print("VPC deleted on AWS")
                    break
                except ClientError as e:
                    if e.response['Error']['Code'] == 'DependencyViolation':
                        wait_time = 2 ** attempt
                        print("DependencyViolation encountered. Retrying in", wait_time, "seconds")
                        time.sleep(wait_time)
                    else:
                        print("Unexpected error deleting VPC:", e)
                        raise
            else:
                # If after retries deletion still failed, log an error and do not delete from DB
                print("Failed to delete VPC on AWS after multiple attempts.")
                return JsonResponse({'status': 'error', 'message': 'Failed to delete VPC on AWS'})

            print("Deleting VPC record from database")
            vpc.delete()
            return JsonResponse({'status': 'success'})

        except ClientError as e:
            print("Error during deletion:", str(e))
            return JsonResponse({'status': 'error', 'message': str(e)})
    else:
        print("Invalid request method or missing AJAX header:", request.method)
        return JsonResponse({'status': 'error', 'message': 'Invalid request'})


def api_test_form(request):
    return render(request, 'name_app/api_test_form.html')


def process_api_form(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        vpc_name = request.POST.get('vpc_name')
        vpc_cidr = request.POST.get('vpc_cidr')
        subnet_cidrs = request.POST.get('subnet_cidrs')
        availability_zones = request.POST.get('availability_zones')

        if not all([username, password, vpc_name, vpc_cidr, subnet_cidrs, availability_zones]):
            return HttpResponse("Missing required fields")

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return HttpResponse("User not found")

        if not user.check_password(password):
            return HttpResponse("Invalid password")

        vpc_id = create_vpc(vpc_cidr, subnet_cidrs.split(','), availability_zones.split(','), vpc_name)
        VPC.objects.create(user=user, vpc_id=vpc_id, vpc_name=vpc_name)
        all_vpcs = VPC.objects.all()

        return render(request, 'name_app/api_test_result.html', {
            'vpc_id': vpc_id,
            'vpc_name': vpc_name,
            'all_vpcs': all_vpcs
        })
    else:
        return redirect('api_test_form')


def create_user_page(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        email = request.POST.get('email')

        if not all([username, password, email]):
            messages.error(request, 'Please fill in all fields.')
            return render(request, 'name_app/create_user.html')

        User.objects.create_user(username=username, password=password, email=email)
        messages.success(request, 'User created successfully.')
        return redirect('create_user_page')

    return render(request, 'name_app/create_user.html')
