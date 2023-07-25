from django.shortcuts import render
from rest_framework.response import Response
from rest_framework.views import APIView
from .serializers import (
    UserRegistrtionSerializer, 
    UserLoginSerializer, 
    UserProfileSerializer,
    UserChangePasswordSerializer,
    SendPasswordRequestEmailSerializer,
    UserPasswordResetSerializer,
)
from rest_framework import status
from django.contrib.auth import authenticate
from .renderers import UserRenderer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from rest_framework import generics
from .models import User

# Manually token generation
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

# Create your views here.
class UserRegistrationView(APIView):
    renderer_classes = [UserRenderer]

    def post(self, request, format=None):
        serializer = UserRegistrtionSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            token = get_tokens_for_user(user)
            return Response(
                {'token':token, 'message': 'Registration successful'},
                status=status.HTTP_201_CREATED
            )
        return Response(
            serializer.errors, 
            status=status.HTTP_400_BAD_REQUEST
        )
        

class UserLoginView(APIView):
    def post(self, request, format=None):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.data['email']
            password = serializer.data['password']
            user = authenticate(email=email, password=password)
            if user is not None:
                token = get_tokens_for_user(user)
                return Response(
                    {'token':token, 'message': 'Login Successfully'}, 
                    status=status.HTTP_200_OK
                )
            else:
                return Response(
                    {'errors': 
                        {'non_fields_errors': 'Email or Password is not valid'}
                    }, 
                    status=status.HTTP_400_BAD_REQUEST
                )
        # print(serializer.errors)
        return Response(
            serializer.errors, 
            status=status.HTTP_400_BAD_REQUEST
        )


class UserProfileView(generics.ListCreateAPIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def get(self, request, format=None):
        serializer = UserProfileSerializer(request.user)
        return Response(
            serializer.data, 
            status=status.HTTP_200_OK
        )
    
class allData(generics.ListCreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserProfileSerializer
    
    
class UserChangePasswordView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def post(self, request, format=None):
        serializer = UserChangePasswordSerializer(
            data=request.data, 
            context={'user': request.user}
        )
        if serializer.is_valid():
            return Response(
                {'message': 'Password changed successfully'},
                status=status.HTTP_200_OK
            )
        return Response(
            serializer.errors, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    
class SendPasswordRequestEmailView(APIView):
    def post(self, request, format=None):
        serializer = SendPasswordRequestEmailSerializer(data=request.data)
        if serializer.is_valid():
            return Response(
                {'message': 'Password Reset link send. Please check your Email'},
                status=status.HTTP_200_OK
            )
        return Response(
            serializer.errors, 
            status=status.HTTP_400_BAD_REQUEST
        )

class UserPasswordResetView(APIView):
    def post(self, request, uid, token, format=None):
        seializer = UserPasswordResetSerializer(
            data=request.data,
            context={'uid': uid, 'token': token},
        )

        if seializer.is_valid():
            return Response(
                {'message': 'Password reset successful'},
                status=status.HTTP_200_OK,
            )
        return Response(
            seializer.errors,
            status=status.HTTP_400_BAD_REQUEST
        )