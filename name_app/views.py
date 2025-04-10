import boto3
import time
import ipaddress
from django.http import JsonResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.models import User
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from rest_framework.views import APIView
from botocore.exceptions import ClientError
from .models import VPC

ec2 = boto3.client('ec2')


def create_vpc(cidr_block, subnet_cidr_blocks, availability_zones, vpc_name):
    """Create a VPC and its associated resources. If any error occurs, attempt to clean up."""
    vpc_id = None
    igw_id = None
    created_subnet_ids = []
    route_table_id = None

    # Validate CIDRs before calling AWS
    try:
        ipaddress.IPv4Network(cidr_block.strip(), strict=False)
        for subnet in subnet_cidr_blocks:
            ipaddress.IPv4Network(subnet.strip(), strict=False)
    except ValueError as e:
        raise Exception(f"Invalid CIDR block input: {e}")

    try:
        # Create VPC
        response = ec2.create_vpc(
            CidrBlock=cidr_block,
            TagSpecifications=[{
                'ResourceType': 'vpc',
                'Tags': [{'Key': 'Name', 'Value': vpc_name}]
            }]
        )
        vpc_id = response['Vpc']['VpcId']
        print("Created VPC:", vpc_id)

        # Create Subnets
        for subnet_cidr, az in zip(subnet_cidr_blocks, availability_zones):
            subnet_response = ec2.create_subnet(
                VpcId=vpc_id,
                CidrBlock=subnet_cidr.strip(),
                AvailabilityZone=az.strip()
            )
            subnet_id = subnet_response['Subnet']['SubnetId']
            created_subnet_ids.append(subnet_id)
            print("Created Subnet:", subnet_id)

        # Create and attach Internet Gateway
        igw_response = ec2.create_internet_gateway()
        igw_id = igw_response['InternetGateway']['InternetGatewayId']
        ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
        print("Attached Internet Gateway:", igw_id)

        # Create Route Table and Route
        route_table_response = ec2.create_route_table(VpcId=vpc_id)
        route_table_id = route_table_response['RouteTable']['RouteTableId']
        ec2.create_route(
            RouteTableId=route_table_id,
            DestinationCidrBlock='0.0.0.0/0',
            GatewayId=igw_id
        )
        print("Created route table and route")

        # Associate Route Table with first subnet
        subnets = ec2.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])['Subnets']
        if subnets:
            ec2.associate_route_table(RouteTableId=route_table_id, SubnetId=subnets[0]['SubnetId'])
            print("Associated route table with subnet:", subnets[0]['SubnetId'])

        return vpc_id

    except ClientError as e:
        # Cleanup any resources that were created
        print("Error creating VPC:", e)
        if route_table_id:
            try:
                ec2.delete_route_table(RouteTableId=route_table_id)
            except Exception as cleanup_err:
                print("Error cleaning up route table:", cleanup_err)
        for subnet_id in created_subnet_ids:
            try:
                ec2.delete_subnet(SubnetId=subnet_id)
            except Exception as cleanup_err:
                print("Error cleaning up subnet:", cleanup_err)
        if igw_id:
            try:
                ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
                ec2.delete_internet_gateway(InternetGatewayId=igw_id)
            except Exception as cleanup_err:
                print("Error cleaning up Internet Gateway:", cleanup_err)
        if vpc_id:
            try:
                ec2.delete_vpc(VpcId=vpc_id)
            except Exception as cleanup_err:
                print("Error cleaning up VPC:", cleanup_err)
        raise Exception(f"Error creating VPC: {e}")


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

        try:
            ipaddress.IPv4Network(cidr_block.strip(), strict=False)
            for cidr in subnet_cidr_blocks:
                ipaddress.IPv4Network(cidr.strip(), strict=False)
        except Exception as e:
            return Response({'error': f"Invalid CIDR: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            vpc_id = create_vpc(cidr_block, subnet_cidr_blocks, availability_zones, vpc_name)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

        VPC.objects.create(user=request.user, vpc_id=vpc_id, vpc_name=vpc_name)
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
    if request.method == 'POST' and request.headers.get('x-requested-with') == 'XMLHttpRequest':
        vpc = get_object_or_404(VPC, vpc_id=vpc_id)
        try:
            try:
                ec2.describe_vpcs(VpcIds=[vpc_id])
            except ClientError as e:
                if "InvalidVpcID.NotFound" in str(e):
                    vpc.delete()
                    return JsonResponse({'status': 'success', 'message': 'VPC not found in AWS. Removed from database.'})
                raise

            def safe_delete(fn, id_label, items):
                for item in items:
                    try:
                        fn(**{id_label: item})
                    except ClientError as e:
                        print(f"Error deleting {id_label} {item}: {e}")

            instances = [
                inst['InstanceId'] for r in ec2.describe_instances(
                    Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
                )['Reservations'] for inst in r['Instances']
            ]
            if instances:
                ec2.terminate_instances(InstanceIds=instances)
                ec2.get_waiter('instance_terminated').wait(
                    InstanceIds=instances,
                    WaiterConfig={'Delay': 10, 'MaxAttempts': 12}
                )

            safe_delete(ec2.delete_subnet, 'SubnetId', [
                s['SubnetId'] for s in ec2.describe_subnets(
                    Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
                )['Subnets']
            ])

            for igw in ec2.describe_internet_gateways(
                Filters=[{'Name': 'attachment.vpc-id', 'Values': [vpc_id]}]
            )['InternetGateways']:
                try:
                    ec2.detach_internet_gateway(InternetGatewayId=igw['InternetGatewayId'], VpcId=vpc_id)
                    ec2.delete_internet_gateway(InternetGatewayId=igw['InternetGatewayId'])
                except ClientError as e:
                    print(f"Error deleting IGW: {e}")

            for sg in ec2.describe_security_groups(
                Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
            )['SecurityGroups']:
                if sg['GroupName'] != 'default':
                    safe_delete(ec2.delete_security_group, 'GroupId', [sg['GroupId']])

            for attempt in range(5):
                try:
                    ec2.delete_vpc(VpcId=vpc_id)
                    break
                except ClientError as e:
                    if e.response['Error']['Code'] == 'DependencyViolation':
                        time.sleep(2 ** attempt)
                        continue
                    raise
            else:
                return JsonResponse({'status': 'error', 'message': 'Failed to delete VPC after retries.'})

            vpc.delete()
            return JsonResponse({'status': 'success', 'message': 'VPC deleted successfully.'})

        except ClientError as e:
            return JsonResponse({'status': 'error', 'message': str(e)})

    return JsonResponse({'status': 'error', 'message': 'Invalid request method or not AJAX'})


def front_page(request):
    return render(request, 'name_app/front_page.html')


def api_test_form(request):
    return render(request, 'name_app/api_test_form.html')


def api_test_result(request):
    vpcs = []
    error_message = None
    try:
        response = ec2.describe_vpcs()
        for vpc in response.get('Vpcs', []):
            vpcs.append({
                'VpcId': vpc.get('VpcId'),
                'CidrBlock': vpc.get('CidrBlock'),
                'State': vpc.get('State'),
                'IsDefault': vpc.get('IsDefault'),
                'Tags': vpc.get('Tags', [])
            })
    except ClientError as e:
        error_message = "Error retrieving VPCs from AWS."

    all_vpcs = VPC.objects.all()
    return render(request, 'name_app/api_test_result.html', {
        'vpcs': vpcs,
        'all_vpcs': all_vpcs,
        'error': error_message
    })


def process_api_form(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        vpc_name = request.POST.get('vpc_name')
        vpc_cidr = request.POST.get('vpc_cidr')
        subnet_cidrs = request.POST.get('subnet_cidrs')
        availability_zones = request.POST.get('availability_zones')

        if not all([username, password, vpc_name, vpc_cidr, subnet_cidrs, availability_zones]):
            return render(request, 'name_app/api_test_result.html', {
                'error': "Missing required fields"
            })

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return render(request, 'name_app/api_test_result.html', {
                'error': "User not found"
            })

        if not user.check_password(password):
            return render(request, 'name_app/api_test_result.html', {
                'error': "Invalid password"
            })

        try:
            ipaddress.IPv4Network(vpc_cidr.strip(), strict=False)
        except ValueError:
            return render(request, 'name_app/api_test_result.html', {
                'error': f"Invalid VPC CIDR: {vpc_cidr}"
            })

        subnet_list = [s.strip() for s in subnet_cidrs.split(',') if s.strip()]
        az_list = [z.strip() for z in availability_zones.split(',') if z.strip()]

        if len(subnet_list) != len(az_list):
            return render(request, 'name_app/api_test_result.html', {
                'error': "Number of subnet CIDRs and availability zones must match."
            })

        for subnet_cidr in subnet_list:
            try:
                ipaddress.IPv4Network(subnet_cidr, strict=False)
            except ValueError:
                return render(request, 'name_app/api_test_result.html', {
                    'error': f"Invalid Subnet CIDR: {subnet_cidr}"
                })

        try:
            vpc_id = create_vpc(vpc_cidr, subnet_list, az_list, vpc_name)
            if not vpc_id.startswith("vpc-"):
                raise Exception(vpc_id)
            VPC.objects.create(user=user, vpc_id=vpc_id, vpc_name=vpc_name)
            all_vpcs = VPC.objects.all()
            return render(request, 'name_app/api_test_result.html', {
                'vpc_id': vpc_id,
                'vpc_name': vpc_name,
                'all_vpcs': all_vpcs
            })
        except Exception as e:
            return render(request, 'name_app/api_test_result.html', {
                'error': f"Error creating VPC: {str(e)}"
            })

    return redirect('api_test_form')


def create_user_page(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        email = request.POST.get('email')

        password_errors = []
        if not password:
            password_errors.append("Password is required.")
        else:
            if len(password) < 8:
                password_errors.append("Needs at least 8 characters.")
            if not any(c.isupper() for c in password):
                password_errors.append("Needs at least one uppercase letter.")
            if not any(c in "!@#$%^&*" for c in password):
                password_errors.append("Needs a special character.")

        if password_errors:
            error_message = "Password Requirements Not Met: " + ", ".join(password_errors)
            return render(request, 'name_app/create_user.html', {'error_message': error_message})

        if not all([username, email]):
            messages.error(request, 'Username and email are required.')
        else:
            try:
                User.objects.create_user(username=username, password=password, email=email)
                messages.success(request, 'User created successfully.')
                return redirect('create_user_page')
            except Exception as e:
                messages.error(request, f'Error creating user: {e}')

    return render(request, 'name_app/create_user.html')
