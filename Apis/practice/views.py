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

class LoginView(APIView):
    """
    POST /api/auth/login/
    Validates credentials, returns JWT tokens + user info.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {"success": False, "errors": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )

        username = serializer.validated_data['username']
        password = serializer.validated_data['password']

        user = authenticate(request, username=username, password=password)

        if user is None:
            return Response(
                {"success": False, "error": "Invalid username or password."},
                status=status.HTTP_401_UNAUTHORIZED
            )

        if not user.is_active:
            return Response(
                {"success": False, "error": "This account has been deactivated."},
                status=status.HTTP_403_FORBIDDEN
            )

        tokens = get_tokens_for_user(user)
        user_data = UserDetailSerializer(user).data

        return Response({
            "success": True,
            "message": "Login successful.",
            "user": user_data,
            "tokens": tokens,
        }, status=status.HTTP_200_OK)


# ─────────────────────────────────────────────
# Logout View
# ─────────────────────────────────────────────

class LogoutView(APIView):
    """
    POST /api/auth/logout/
    Blacklists the provided refresh token in the database.
    Requires: Authorization: Bearer <access_token>
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = LogoutSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {"success": False, "errors": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )

        raw_token = serializer.validated_data['refresh']

        try:
            token = RefreshToken(raw_token)
        except TokenError as e:
            return Response(
                {"success": False, "error": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

        if BlacklistedToken.objects.filter(token=raw_token).exists():
            return Response(
                {"success": False, "error": "Token is already blacklisted."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Persist in our custom DB blacklist
        BlacklistedToken.objects.create(user=request.user, token=raw_token)

        # Also blacklist via simplejwt if configured
        try:
            token.blacklist()
        except Exception:
            pass

        return Response({
            "success": True,
            "message": "Logged out successfully."
        }, status=status.HTTP_200_OK)


# ─────────────────────────────────────────────
# Profile View (GET + PUT)
# ─────────────────────────────────────────────

class ProfileView(APIView):
    """
    GET /api/auth/profile/  → returns authenticated user's full profile
    PUT /api/auth/profile/  → update user + profile fields
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = UserDetailSerializer(request.user)
        return Response({
            "success": True,
            "user": serializer.data,
        }, status=status.HTTP_200_OK)

    def put(self, request):
        serializer = UpdateProfileSerializer(
            instance=request.user,
            data=request.data,
            partial=True,
            context={'request': request}
        )
        if not serializer.is_valid():
            return Response(
                {"success": False, "errors": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer.save()
        user_data = UserDetailSerializer(request.user).data
        return Response({
            "success": True,
            "message": "Profile updated successfully.",
            "user": user_data,
        }, status=status.HTTP_200_OK)


# ─────────────────────────────────────────────
# All Users View
# ─────────────────────────────────────────────

class UserListView(generics.ListAPIView):
    """
    GET /api/auth/users/
    Returns a list of all registered users with their profiles.
    """
    permission_classes = [IsAuthenticated]
    serializer_class = UserDetailSerializer
    queryset = User.objects.select_related('profile').all().order_by('-date_joined')
