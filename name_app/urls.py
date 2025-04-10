from django.urls import path
from . import views

urlpatterns = [
    path('api/get_user_token/', views.generate_token, name='get_user_token_api'),
    path('api/create_vpc/', views.WrappedAPIView.as_view(), name='create_vpc_api'),
    path('api/delete_vpc/<str:vpc_id>/', views.delete_vpc, name='delete_vpc_api'),
    path('api_test_form/', views.api_test_form, name='api_test_form'),
    path('process_api_form/', views.process_api_form, name='process_api_form'),
    path('create_user/', views.create_user_page, name='create_user_page'),
    path('view_vpcs/', views.api_test_result, name='api_test_result'),
    path('', views.front_page, name='front_page'),
]
