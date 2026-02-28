from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers

from .models import userprofile

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields=['bio', 'phone', 'created_at ', 'updated_at']
        read_only = ['created_at ', 'updated_at']

class RegisterSerializer(serializers.ModelSerializer):
    password=serializers.CharField(write_only=True, required = True , 
                                   validators=[validate_password], style={'input type': 'passwords'})
    password2=serializers.CharField(write_only=True, required = True , 
                                   label='Confirm Password', style={'input type': 'passwords'})
    bio=serializers.CharField(required=False, allow_blank=True)
    phone=serializers.CharField(required=False, allow_blank=True)
    class Meta:
        Model=User
        fields=['username', 'email', 'firstname','lastname','password', 'password2', 'bio',  'phone' ]
        
    def validate_email(self, value):
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return value

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Passwords do not match."})
        return attrs

    def create(self, validated_data):
        bio = validated_data.pop('bio', '')
        phone = validated_data.pop('phone', '')
        validated_data.pop('password2')

        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data.get('email', ''),
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', ''),
            password=validated_data['password'],
        )
        userprofile.objects.create(user=user, bio=bio, phone=phone)
        return user


# ─────────────────────────────────────────────
# Login Serializer
# ─────────────────────────────────────────────

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(
        required=True,
        write_only=True,
        style={'input_type': 'password'}
    )


# ─────────────────────────────────────────────
# User Detail Serializer
# ─────────────────────────────────────────────

class UserDetailSerializer(serializers.ModelSerializer):
    profile = UserProfileSerializer(read_only=True)

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name',
                  'is_active', 'date_joined', 'profile']
        read_only_fields = ['id', 'is_active', 'date_joined']


# ─────────────────────────────────────────────
# Update Profile Serializer
# ─────────────────────────────────────────────

class UpdateProfileSerializer(serializers.ModelSerializer):
    bio = serializers.CharField(source='profile.bio', required=False, allow_blank=True)
    phone = serializers.CharField(source='profile.phone', required=False, allow_blank=True)
    profile_picture = serializers.URLField(source='profile.profile_picture', required=False, allow_blank=True)

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'bio', 'phone', 'profile_picture']

    def validate_email(self, value):
        user = self.context['request'].user
        if User.objects.filter(email=value).exclude(pk=user.pk).exists():
            raise serializers.ValidationError("This email is already taken.")
        return value

    def update(self, instance, validated_data):
        profile_data = validated_data.pop('profile', {})

        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)
        instance.email = validated_data.get('email', instance.email)
        instance.save()

        profile = instance.profile
        profile.bio = profile_data.get('bio', profile.bio)
        profile.phone = profile_data.get('phone', profile.phone)
        profile.profile_picture = profile_data.get('profile_picture', profile.profile_picture)
        profile.save()

        return instance


# ─────────────────────────────────────────────
# Logout Serializer
# ─────────────────────────────────────────────

class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField(required=True, help_text="Refresh token to blacklist.")
