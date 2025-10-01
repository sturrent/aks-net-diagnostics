"""
Input validation utilities
"""

import re
from pathlib import Path
from typing import List
from .exceptions import ValidationError

# Configuration constants
MAX_FILENAME_LENGTH = 50
MAX_RESOURCE_NAME_LENGTH = 260
ALLOWED_AZ_COMMANDS = {
    'account', 'aks', 'network', 'vmss', 'vm'
}


class InputValidator:
    """Validates user inputs and Azure CLI commands"""
    
    @staticmethod
    def validate_azure_cli_command(cmd: List[str]) -> None:
        """
        Validate Azure CLI command to prevent injection attacks
        
        Args:
            cmd: Command as list of strings
            
        Raises:
            ValidationError: If command is invalid or potentially dangerous
        """
        if not cmd or not isinstance(cmd, list):
            raise ValidationError("Command must be a non-empty list")
        
        # Check if the first argument is an allowed command
        if cmd[0] not in ALLOWED_AZ_COMMANDS:
            raise ValidationError(f"Command '{cmd[0]}' is not allowed")
        
        # Validate that arguments don't contain shell metacharacters
        dangerous_chars = ['|', '&', ';', '(', ')', '$', '`', '\\', '"', "'", '<', '>']
        for arg in cmd:
            if any(char in str(arg) for char in dangerous_chars):
                # Allow some safe characters in specific contexts
                if not InputValidator._is_safe_argument(str(arg)):
                    raise ValidationError(
                        f"Command argument contains potentially dangerous characters: {arg}"
                    )
    
    @staticmethod
    def _is_safe_argument(arg: str) -> bool:
        """Check if an argument with special characters is safe"""
        # Allow Azure resource IDs which contain forward slashes
        if arg.startswith('/subscriptions/'):
            return True
        # Allow JSON queries which might contain quotes
        if arg.startswith('[') and arg.endswith(']'):
            return True
        return False
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """
        Sanitize filename to prevent path traversal and invalid characters
        
        Args:
            filename: Original filename
            
        Returns:
            Sanitized filename
        """
        # Remove path separators and other dangerous characters
        dangerous_chars = ['/', '\\', '..', '<', '>', ':', '"', '|', '?', '*']
        sanitized = filename
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '_')
        
        # Limit length and ensure it's not empty
        sanitized = sanitized[:MAX_FILENAME_LENGTH].strip()
        if not sanitized:
            sanitized = "unknown"
        
        return sanitized
    
    @staticmethod
    def validate_output_path(filepath: str) -> str:
        """
        Validate and sanitize output file path
        
        Args:
            filepath: User-provided file path
            
        Returns:
            Validated file path
            
        Raises:
            ValidationError: If path is invalid or unsafe
        """
        # Resolve the path to prevent traversal attacks
        resolved_path = Path(filepath).expanduser().resolve()
        current_dir = Path.cwd().resolve()
        
        try:
            resolved_path.relative_to(current_dir)
        except ValueError:
            raise ValidationError("Output file path must be within the current directory")
        
        # Ensure the filename has a safe extension
        if not str(resolved_path).lower().endswith('.json'):
            resolved_path = resolved_path.with_suffix('.json')
        
        return str(resolved_path)
    
    @staticmethod
    def validate_resource_name(name: str, resource_type: str) -> str:
        """
        Validate Azure resource name
        
        Args:
            name: Resource name
            resource_type: Type of resource (for error messages)
            
        Returns:
            Validated resource name
            
        Raises:
            ValidationError: If name is invalid
        """
        if not name or not isinstance(name, str):
            raise ValidationError(f"{resource_type.capitalize()} cannot be empty")
        
        # Remove leading/trailing whitespace
        name = name.strip()
        
        # Basic length validation
        if len(name) < 1 or len(name) > MAX_RESOURCE_NAME_LENGTH:
            raise ValidationError(
                f"{resource_type.capitalize()} must be between 1 and 260 characters"
            )
        
        # Check for obviously malicious patterns
        dangerous_patterns = ['../', '\\', '<script>', 'javascript:', 'data:']
        for pattern in dangerous_patterns:
            if pattern.lower() in name.lower():
                raise ValidationError(
                    f"{resource_type.capitalize()} contains invalid characters"
                )
        
        return name
    
    @staticmethod
    def validate_subscription_id(subscription_id: str) -> str:
        """
        Validate Azure subscription ID format
        
        Args:
            subscription_id: Subscription ID or name
            
        Returns:
            Validated subscription ID
            
        Raises:
            ValidationError: If subscription ID is invalid
        """
        if not subscription_id:
            raise ValidationError("Subscription ID cannot be empty")
        
        # Basic GUID format validation (loose)
        guid_pattern = r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
        
        if not re.match(guid_pattern, subscription_id):
            # Allow subscription names as well, not just GUIDs
            if len(subscription_id) < 1 or len(subscription_id) > 100:
                raise ValidationError("Invalid subscription ID format")
        
        return subscription_id
