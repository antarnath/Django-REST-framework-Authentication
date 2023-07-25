from rest_framework import serializers
from .models import User

# Verification email
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, smart_str
from django.contrib.auth.tokens import (
    default_token_generator,
    PasswordResetTokenGenerator,
)
from .utils import Util


class UserRegistrtionSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(
        max_length=255,
        style={"input_type": "password"}, 
        write_only=True
    )
    class Meta:
        model = User
        fields = ['email', 'name', 'password', 'password2', 'tc']
        extra_kwargs = {
            'password': {'write_only': True}
        }
        
    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        
        if password != password2:
            raise serializers.ValidationError({'errors': 'password does not match'})
        return attrs
    
    def create(self, validated_data):
        name = validated_data['name']
        email = validated_data['email']
        password = validated_data['password']
        tc = validated_data['tc']

        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError({'error': 'Email already exists'})

        user = User.objects.create(
            name=name, 
            email=email, 
            tc=tc
        )
        user.set_password(password)
        user.save()

        return user
    
class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        model = User
        fields = ['email', 'password']
        
        
class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User 
        fields = ['id', 'name', 'email']
        
        
class UserChangePasswordSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        max_length=255,
        style={'input_type': 'password'},
        write_only=True
    )
    password2 = serializers.CharField(
        max_length=255,
        style={'input_type': 'password'},
        write_only=True
    )
    class Meta:
        model = User
        fields = ['password', 'password2']
        
    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        user = self.context.get('user')
        if password != password2:
            raise serializers.ValidationError({'errors': 'password does not match'})
        user.set_password(password)
        user.save()
        return attrs
    
class SendPasswordRequestEmailSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)
    
    class Meta:
        model = User
        fields = ['email']
        
    def validate(self, attrs):
        email = attrs.get('email')
        if User.objects.filter(email=email).exists:
            user = User.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            print("Encoded UID: ", uid)
            token = PasswordResetTokenGenerator().make_token(user)
            print("Password reset token: ", token)
            link = 'http://127.0.0.1:8000/api/user/reset-password/'+uid+'/'+token
            print('Password reset link:', link)
            
            #send email 
            subject: 'Please activate your account'
            body = 'Click follwing Link to reset your password ' + link
            data = {
                'subject': 'Please activate your account',
                'body': body,
                'to_email': user.email,
            }
            Util.send_email(data)
        else:
            raise ValidationError('Your are not a Registered User')
        return attrs
    

class UserPasswordResetSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        max_length=255,
        style={'input_type': 'password'},
        write_only=True
    )
    password2 = serializers.CharField(
        max_length=255,
        style={'input_type': 'password'},
        write_only=True
    )
    class Meta:
        model = User
        fields = ['password', 'password2']
        
    def validate(self, attrs):
        try:
            password = attrs.get('password')
            password2 = attrs.get('password2')
            uid = self.context.get('uid')
            token = self.context.get('token')
            if password != password2:
                raise serializers.ValidationError({'errors': 'password does not match'})
            id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise ValueError('Validation link is expired')   
            user.set_password(password)
            user.save()
            return attrs
        except DjangoUnicodeDecodeError as indentifier:
            PasswordResetTokenGenerator().check_token(user, token)
            raise ValueError('Validation link is expired')  