#!/usr/bin/env python3
"""
Configuration Management for Vulnerability Scanner
Production-ready configuration with environment variables and validation
"""

import os
import json
import logging
from typing import Dict, Any, Optional
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

@dataclass
class ScannerConfig:
    """Configuration class for the vulnerability scanner"""
    
    # Scanner settings
    max_workers: int = 10
    timeout: int = 30
    rate_limit: int = 100
    rate_window: int = 3600
    
    # Security settings
    enable_javascript: bool = True
    enable_ai_detection: bool = True
    enable_deep_scan: bool = False
    max_scan_depth: int = 3
    
    # Report settings
    report_formats: list = field(default_factory=lambda: ['html', 'json'])
    output_directory: str = './reports'
    
    # Web server settings
    web_host: str = '0.0.0.0'
    web_port: int = 8080
    debug_mode: bool = False
    
    # Authentication settings
    enable_auth: bool = False
    jwt_secret: str = 'change-me-in-production'
    session_timeout: int = 3600
    
    # API settings
    api_authentication: bool = False
    api_rate_limit: int = 60
    api_rate_window: int = 60
    
    # External services
    shodan_api_key: Optional[str] = None
    virustotal_api_key: Optional[str] = None
    
    # Logging settings
    log_level: str = 'INFO'
    log_file: str = 'scanner.log'
    log_max_size: int = 10 * 1024 * 1024  # 10MB
    log_backup_count: int = 5
    
    # Advanced settings
    user_agent: str = 'VulnScanner/2.0 (Security Testing)'
    follow_redirects: bool = True
    verify_ssl: bool = True
    request_delay: float = 0.1
    
    @classmethod
    def from_env(cls) -> 'ScannerConfig':
        """Create configuration from environment variables"""
        config = cls()
        
        # Scanner settings
        config.max_workers = int(os.getenv('VULN_SCANNER_WORKERS', config.max_workers))
        config.timeout = int(os.getenv('VULN_SCANNER_TIMEOUT', config.timeout))
        config.rate_limit = int(os.getenv('VULN_SCANNER_RATE_LIMIT', config.rate_limit))
        config.rate_window = int(os.getenv('VULN_SCANNER_RATE_WINDOW', config.rate_window))
        
        # Security settings
        config.enable_javascript = os.getenv('VULN_SCANNER_ENABLE_JS', 'true').lower() == 'true'
        config.enable_ai_detection = os.getenv('VULN_SCANNER_ENABLE_AI', 'true').lower() == 'true'
        config.enable_deep_scan = os.getenv('VULN_SCANNER_DEEP_SCAN', 'false').lower() == 'true'
        config.max_scan_depth = int(os.getenv('VULN_SCANNER_MAX_DEPTH', config.max_scan_depth))
        
        # Report settings
        formats = os.getenv('VULN_SCANNER_REPORT_FORMATS', ','.join(config.report_formats))
        config.report_formats = [f.strip() for f in formats.split(',')]
        config.output_directory = os.getenv('VULN_SCANNER_OUTPUT_DIR', config.output_directory)
        
        # Web server settings
        config.web_host = os.getenv('VULN_SCANNER_HOST', config.web_host)
        config.web_port = int(os.getenv('VULN_SCANNER_PORT', config.web_port))
        config.debug_mode = os.getenv('VULN_SCANNER_DEBUG', 'false').lower() == 'true'
        
        # Authentication settings
        config.enable_auth = os.getenv('VULN_SCANNER_ENABLE_AUTH', 'false').lower() == 'true'
        config.jwt_secret = os.getenv('VULN_SCANNER_JWT_SECRET', config.jwt_secret)
        config.session_timeout = int(os.getenv('VULN_SCANNER_SESSION_TIMEOUT', config.session_timeout))
        
        # API settings
        config.api_authentication = os.getenv('VULN_SCANNER_API_AUTH', 'false').lower() == 'true'
        config.api_rate_limit = int(os.getenv('VULN_SCANNER_API_RATE_LIMIT', config.api_rate_limit))
        config.api_rate_window = int(os.getenv('VULN_SCANNER_API_RATE_WINDOW', config.api_rate_window))
        
        # External services
        config.shodan_api_key = os.getenv('SHODAN_API_KEY')
        config.virustotal_api_key = os.getenv('VIRUSTOTAL_API_KEY')
        
        # Logging settings
        config.log_level = os.getenv('VULN_SCANNER_LOG_LEVEL', config.log_level)
        config.log_file = os.getenv('VULN_SCANNER_LOG_FILE', config.log_file)
        config.log_max_size = int(os.getenv('VULN_SCANNER_LOG_MAX_SIZE', config.log_max_size))
        config.log_backup_count = int(os.getenv('VULN_SCANNER_LOG_BACKUP_COUNT', config.log_backup_count))
        
        # Advanced settings
        config.user_agent = os.getenv('VULN_SCANNER_USER_AGENT', config.user_agent)
        config.follow_redirects = os.getenv('VULN_SCANNER_FOLLOW_REDIRECTS', 'true').lower() == 'true'
        config.verify_ssl = os.getenv('VULN_SCANNER_VERIFY_SSL', 'true').lower() == 'true'
        config.request_delay = float(os.getenv('VULN_SCANNER_REQUEST_DELAY', config.request_delay))
        
        return config
    
    @classmethod
    def from_file(cls, config_file: str) -> 'ScannerConfig':
        """Create configuration from JSON file"""
        try:
            with open(config_file, 'r') as f:
                config_data = json.load(f)
            
            config = cls()
            for key, value in config_data.items():
                if hasattr(config, key):
                    setattr(config, key, value)
                else:
                    logger.warning(f"Unknown configuration key: {key}")
            
            return config
            
        except FileNotFoundError:
            logger.warning(f"Configuration file not found: {config_file}")
            return cls()
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON in configuration file: {config_file}")
            return cls()
    
    def save_to_file(self, config_file: str) -> None:
        """Save configuration to JSON file"""
        try:
            config_data = {
                'max_workers': self.max_workers,
                'timeout': self.timeout,
                'rate_limit': self.rate_limit,
                'rate_window': self.rate_window,
                'enable_javascript': self.enable_javascript,
                'enable_ai_detection': self.enable_ai_detection,
                'enable_deep_scan': self.enable_deep_scan,
                'max_scan_depth': self.max_scan_depth,
                'report_formats': self.report_formats,
                'output_directory': self.output_directory,
                'web_host': self.web_host,
                'web_port': self.web_port,
                'debug_mode': self.debug_mode,
                'enable_auth': self.enable_auth,
                'session_timeout': self.session_timeout,
                'api_authentication': self.api_authentication,
                'api_rate_limit': self.api_rate_limit,
                'api_rate_window': self.api_rate_window,
                'log_level': self.log_level,
                'log_file': self.log_file,
                'log_max_size': self.log_max_size,
                'log_backup_count': self.log_backup_count,
                'user_agent': self.user_agent,
                'follow_redirects': self.follow_redirects,
                'verify_ssl': self.verify_ssl,
                'request_delay': self.request_delay
            }
            
            with open(config_file, 'w') as f:
                json.dump(config_data, f, indent=2)
            
            logger.info(f"Configuration saved to {config_file}")
            
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")
    
    def validate(self) -> bool:
        """Validate configuration values"""
        errors = []
        
        # Validate numeric ranges
        if self.max_workers < 1 or self.max_workers > 50:
            errors.append("max_workers must be between 1 and 50")
        
        if self.timeout < 5 or self.timeout > 300:
            errors.append("timeout must be between 5 and 300 seconds")
        
        if self.rate_limit < 1 or self.rate_limit > 1000:
            errors.append("rate_limit must be between 1 and 1000")
        
        if self.max_scan_depth < 1 or self.max_scan_depth > 10:
            errors.append("max_scan_depth must be between 1 and 10")
        
        if self.web_port < 1 or self.web_port > 65535:
            errors.append("web_port must be between 1 and 65535")
        
        if self.request_delay < 0 or self.request_delay > 10:
            errors.append("request_delay must be between 0 and 10 seconds")
        
        # Validate report formats
        valid_formats = ['html', 'json', 'xml', 'csv', 'pdf', 'junit', 'sarif']
        for fmt in self.report_formats:
            if fmt not in valid_formats:
                errors.append(f"Invalid report format: {fmt}")
        
        # Validate log level
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if self.log_level not in valid_levels:
            errors.append(f"Invalid log level: {self.log_level}")
        
        # Validate directories
        try:
            Path(self.output_directory).mkdir(parents=True, exist_ok=True)
        except Exception as e:
            errors.append(f"Cannot create output directory: {e}")
        
        # Log validation errors
        if errors:
            for error in errors:
                logger.error(f"Configuration validation error: {error}")
            return False
        
        return True
    
    def get_scan_config(self) -> Dict[str, Any]:
        """Get configuration specific to scanning"""
        return {
            'max_workers': self.max_workers,
            'timeout': self.timeout,
            'rate_limit': self.rate_limit,
            'rate_window': self.rate_window,
            'enable_javascript': self.enable_javascript,
            'enable_ai_detection': self.enable_ai_detection,
            'enable_deep_scan': self.enable_deep_scan,
            'max_scan_depth': self.max_scan_depth,
            'user_agent': self.user_agent,
            'follow_redirects': self.follow_redirects,
            'verify_ssl': self.verify_ssl,
            'request_delay': self.request_delay,
            'shodan_api_key': self.shodan_api_key,
            'virustotal_api_key': self.virustotal_api_key
        }
    
    def get_web_config(self) -> Dict[str, Any]:
        """Get configuration specific to web server"""
        return {
            'host': self.web_host,
            'port': self.web_port,
            'debug': self.debug_mode,
            'enable_auth': self.enable_auth,
            'jwt_secret': self.jwt_secret,
            'session_timeout': self.session_timeout,
            'api_authentication': self.api_authentication,
            'api_rate_limit': self.api_rate_limit,
            'api_rate_window': self.api_rate_window
        }
    
    def get_logging_config(self) -> Dict[str, Any]:
        """Get configuration specific to logging"""
        return {
            'level': self.log_level,
            'file': self.log_file,
            'max_size': self.log_max_size,
            'backup_count': self.log_backup_count
        }
    
    def __str__(self) -> str:
        """String representation of configuration"""
        return f"ScannerConfig(workers={self.max_workers}, timeout={self.timeout}, port={self.web_port})"


class ConfigManager:
    """Configuration manager for the vulnerability scanner"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file or 'scanner_config.json'
        self.config = None
        self.load_config()
    
    def load_config(self) -> None:
        """Load configuration from file and environment"""
        # First load from file if it exists
        if os.path.exists(self.config_file):
            self.config = ScannerConfig.from_file(self.config_file)
            logger.info(f"Configuration loaded from {self.config_file}")
        else:
            self.config = ScannerConfig()
            logger.info("Using default configuration")
        
        # Override with environment variables
        env_config = ScannerConfig.from_env()
        self.config = self._merge_configs(self.config, env_config)
        
        # Validate configuration
        if not self.config.validate():
            raise ValueError("Configuration validation failed")
    
    def _merge_configs(self, base: ScannerConfig, override: ScannerConfig) -> ScannerConfig:
        """Merge two configurations, with override taking precedence"""
        merged = ScannerConfig()
        
        # Get all attributes from base config
        for key, value in base.__dict__.items():
            setattr(merged, key, value)
        
        # Override with environment values where they differ from defaults
        default_config = ScannerConfig()
        for key, value in override.__dict__.items():
            if hasattr(default_config, key):
                default_value = getattr(default_config, key)
                if value != default_value:
                    setattr(merged, key, value)
        
        return merged
    
    def get_config(self) -> ScannerConfig:
        """Get current configuration"""
        return self.config
    
    def save_config(self) -> None:
        """Save current configuration to file"""
        if self.config:
            self.config.save_to_file(self.config_file)
    
    def reload_config(self) -> None:
        """Reload configuration from file and environment"""
        self.load_config()
    
    def get_config_info(self) -> Dict[str, Any]:
        """Get configuration information for display"""
        if not self.config:
            return {}
        
        return {
            'scanner': self.config.get_scan_config(),
            'web': self.config.get_web_config(),
            'logging': self.config.get_logging_config(),
            'validation': self.config.validate()
        }


def setup_logging(config: ScannerConfig) -> None:
    """Setup logging based on configuration"""
    from logging.handlers import RotatingFileHandler
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Setup root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, config.log_level))
    
    # Clear existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Add console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    # Add file handler with rotation
    try:
        file_handler = RotatingFileHandler(
            config.log_file,
            maxBytes=config.log_max_size,
            backupCount=config.log_backup_count
        )
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
    except Exception as e:
        logger.error(f"Failed to setup file logging: {e}")


def create_sample_config() -> None:
    """Create a sample configuration file"""
    config = ScannerConfig()
    config.save_to_file('scanner_config.sample.json')
    logger.info("Sample configuration created: scanner_config.sample.json")


if __name__ == '__main__':
    # Create sample configuration
    create_sample_config()
    
    # Test configuration loading
    config_manager = ConfigManager()
    config = config_manager.get_config()
    
    print("Configuration loaded successfully:")
    print(config)
    print("\nConfiguration info:")
    info = config_manager.get_config_info()
    for section, data in info.items():
        print(f"\n{section.upper()}:")
        if isinstance(data, dict):
            for key, value in data.items():
                print(f"  {key}: {value}")
        else:
            print(f"  {data}")