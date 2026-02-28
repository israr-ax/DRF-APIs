from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from rest_framework import status, generics
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError

from .models import BlacklistedToken, UserProfile
from .serializer import (
    RegisterSerializer,
    LoginSerializer,
    LogoutSerializer,
    UserDetailSerializer,
    UpdateProfileSerializer,
)

def get_token_for_user(user):
    refresh=RefreshToken.for_user(user)
    return { "access" : str(refresh.access_token),
            "refresh": str(refresh),}
    
class RegisterView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {"success": False, "errors": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST)
        user = serializer.save()
        tokens = get_token_for_user(user)
        return Response ({
            
            "success": True,
            "message": "Account created successfully.",
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
            },
            "tokens": tokens,
        }, status=status.HTTP_201_CREATED)