from functools import wraps
from typing import Callable, List, Any, Optional, Dict, Set, Union
from fastapi import Depends, HTTPException, status
from pydantic import BaseModel

# User data definition
class UserData(BaseModel):
    """
    Standard user data structure for permission checking
    
    This defines the expected fields that permission rules will check against.
    Custom fields can be added as needed.
    """
    id: Optional[str] = None
    roles: Set[str] = set()
    permissions: Set[str] = set()
    is_active: bool = True
    is_authenticated: bool = False
    metadata: Dict[str, Any] = {}
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "UserData":
        """Convert a dictionary to UserData object"""
        return cls(**data)
    
    @classmethod
    def from_object(cls, obj: Any) -> "UserData":
        """
        Convert any object with roles/permissions attributes to UserData
        
        This allows adapting existing user objects to work with permission system
        """
        user_data = cls(
            id=getattr(obj, "id", None),
            is_active=getattr(obj, "is_active", True),
            is_authenticated=getattr(obj, "is_authenticated", False),
        )
        
        # Extract roles
        roles = getattr(obj, "roles", None)
        if roles:
            if isinstance(roles, (list, set, tuple)):
                user_data.roles = set(roles)
            else:
                user_data.roles = {str(roles)}
                
        # Extract permissions
        permissions = getattr(obj, "permissions", None)
        if permissions:
            if isinstance(permissions, (list, set, tuple)):
                user_data.permissions = set(permissions)
            else:
                user_data.permissions = {str(permissions)}
                
        # Extract any additional metadata
        metadata = getattr(obj, "metadata", {})
        if metadata and isinstance(metadata, dict):
            user_data.metadata = metadata
            
        return user_data

# Default error responses
UNAUTHORIZED_EXCEPTION = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Not authenticated",
    headers={"WWW-Authenticate": "Bearer"},
)

FORBIDDEN_EXCEPTION = HTTPException(
    status_code=status.HTTP_403_FORBIDDEN,
    detail="Not enough permissions",
)

# Core permission rule type
PermissionRule = Callable[[Union[UserData, Any]], bool]


def create_rule(
    check_function: Callable[[Any], bool], error_message: Optional[str] = None
) -> PermissionRule:
    """
    Create a permission rule from a check function

    Args:
        check_function: Function that takes a user or context and returns True if permitted
        error_message: Custom error message on failure

    Returns:
        A permission rule function
    """

    @wraps(check_function)
    def rule(context):
        if check_function(context):
            return True
        if error_message:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail=error_message
            )
        raise FORBIDDEN_EXCEPTION

    return rule


def combine_rules(operator: str = "and") -> Callable:
    """
    Create a function that combines multiple permission rules

    Args:
        operator: Either "and" or "or" to determine how rules are combined

    Returns:
        A function that accepts rules and returns a combined rule
    """

    def combiner(*rules: List[PermissionRule]) -> PermissionRule:
        if not rules:
            return lambda _: True

        def combined_rule(context):
            results = [rule(context) for rule in rules]
            if operator == "and":
                return all(results)
            elif operator == "or":
                return any(results)
            return False

        return combined_rule

    return combiner


# Create AND and OR rule combiners
and_rules = combine_rules("and")
or_rules = combine_rules("or")


def allow_all(_) -> bool:
    """Rule that always allows access"""
    return True


def deny_all(_) -> bool:
    """Rule that always denies access"""
    return False


def has_role(required_role: str) -> PermissionRule:
    """
    Check if user has a specific role

    Args:
        required_role: Role name required for access

    Returns:
        Permission rule checking for the role
    """

    def check_role(user):
        # Use UserData methods if it's not a UserData object
        if not isinstance(user, UserData):
            user = UserData.from_object(user)
            
        return required_role in user.roles

    return create_rule(check_role, f"User doesn't have required role: {required_role}")


def has_any_role(required_roles: List[str]) -> PermissionRule:
    """
    Check if user has any of the specified roles

    Args:
        required_roles: List of role names, any of which grants access

    Returns:
        Permission rule checking for any of the roles
    """

    def check_roles(user):
        # Use UserData methods if it's not a UserData object
        if not isinstance(user, UserData):
            user = UserData.from_object(user)
            
        return any(role in user.roles for role in required_roles)

    return create_rule(
        check_roles,
        f"User doesn't have any of the required roles: {', '.join(required_roles)}",
    )


def has_all_roles(required_roles: List[str]) -> PermissionRule:
    """
    Check if user has all of the specified roles

    Args:
        required_roles: List of role names, all of which are required for access

    Returns:
        Permission rule checking for all of the roles
    """

    def check_roles(user):
        # Use UserData methods if it's not a UserData object
        if not isinstance(user, UserData):
            user = UserData.from_object(user)
            
        return all(role in user.roles for role in required_roles)

    return create_rule(
        check_roles,
        f"User doesn't have all required roles: {', '.join(required_roles)}",
    )


def has_permission(required_permission: str) -> PermissionRule:
    """
    Check if user has a specific permission

    Args:
        required_permission: Permission name required for access

    Returns:
        Permission rule checking for the permission
    """

    def check_permission(user):
        # Use UserData methods if it's not a UserData object
        if not isinstance(user, UserData):
            user = UserData.from_object(user)
            
        return required_permission in user.permissions

    return create_rule(
        check_permission,
        f"User doesn't have required permission: {required_permission}",
    )


def parametrized_rule(param_func: Callable) -> Callable:
    """
    Create a parameterized rule factory

    This decorator allows creating rule factories that accept parameters

    Args:
        param_func: Function that takes parameters and returns a rule function

    Returns:
        A parameterized rule factory
    """

    @wraps(param_func)
    def rule_factory(*args, **kwargs):
        return param_func(*args, **kwargs)

    return rule_factory


def require(rule: PermissionRule, get_user: Callable = None):
    """
    Convert a permission rule to a FastAPI dependency

    Args:
        rule: The permission rule to enforce
        get_user: Function to get the user from request (defaults to None)

    Returns:
        A FastAPI dependency that enforces the permission rule
    """

    async def dependency(user: Any = Depends(get_user)):
        if user is None:
            raise UNAUTHORIZED_EXCEPTION

        # Apply the rule to the user
        rule(user)
        return user

    return Depends(dependency)


def guard(rule: PermissionRule):
    """
    Create a decorator to protect functions with a permission rule

    Args:
        rule: The permission rule to enforce

    Returns:
        A decorator that applies the rule before executing the function
    """

    def decorator(func):
        @wraps(func)
        def wrapper(user, *args, **kwargs):
            if user is None:
                raise UNAUTHORIZED_EXCEPTION

            # Apply the rule to the user
            rule(user)
            return func(user, *args, **kwargs)

        return wrapper

    return decorator
