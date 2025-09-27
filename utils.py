import os
import uuid
from datetime import datetime
from flask import request, current_app
from flask_login import current_user
from werkzeug.utils import secure_filename
from models import AuditLog, db


def allowed_file(filename, allowed_extensions):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions


def save_uploaded_file(file, upload_folder=None):
    """Save uploaded file and return the filename"""
    if file and file.filename:
        filename = secure_filename(file.filename)
        name, ext = os.path.splitext(filename)
        unique_filename = f"{name}_{uuid.uuid4().hex[:8]}{ext}"

        if upload_folder is None:
            upload_folder = current_app.config['UPLOAD_FOLDER']

        os.makedirs(upload_folder, exist_ok=True)
        file_path = os.path.join(upload_folder, unique_filename)
        file.save(file_path)
        return unique_filename
    return None


def log_audit(operacao, tabela, id_registro=None, detalhes=None):
    """Log audit trail"""
    try:
        audit = AuditLog(
            usuario=current_user.username if current_user.is_authenticated else 'Sistema',
            operacao=operacao,
            tabela=tabela,
            id_registro=id_registro,
            detalhes=detalhes,
            ip_origem=request.remote_addr if request else None
        )
        db.session.add(audit)
        db.session.commit()
    except Exception as e:
        current_app.logger.error(f"Erro ao registrar auditoria: {e}")


def get_connected_users():
    """Get users who logged in recently (last 5 minutes)"""
    from datetime import timedelta
    from models import User

    five_minutes_ago = datetime.utcnow() - timedelta(minutes=5)
    return User.query.filter(
        User.last_login >= five_minutes_ago,
        User.is_active == True
    ).order_by(User.last_login.desc()).all()


def trim_form_data(form):
    """Apply trim to all string fields in a form"""
    from wtforms import StringField, TextAreaField

    for field_name, field in form._fields.items():
        if isinstance(field, (StringField, TextAreaField)) and field.data:
            field.data = field.data.strip() if field.data else field.data

    return form


def get_statistics():
    """Get system statistics"""
    from models import FTP, SCP, CD, HTTP, Jasppion, S3, MQ, CMD, Formato, HeaderTrailer, JCL, Mail, PRM, SER, Traducao, Perfil, User, FAQ, FTPUsers, MailGroup, Roscoe, AuditLog

    # Protocol counts
    protocol_counts = {
        'ftp': FTP.query.filter_by(is_deleted=False).count(),
        'scp': SCP.query.filter_by(is_deleted=False).count(),
        'cd': CD.query.filter_by(is_deleted=False).count(),
        'http': HTTP.query.filter_by(is_deleted=False).count(),
        'jasppion': Jasppion.query.filter_by(is_deleted=False).count(),
        's3': S3.query.filter_by(is_deleted=False).count(),
        'mq': MQ.query.filter_by(is_deleted=False).count(),
    }

    # Functionality counts
    functionality_counts = {
        'cmd': CMD.query.filter_by(is_deleted=False).count(),
        'formato': Formato.query.filter_by(is_deleted=False).count(),
        'header_trailer': HeaderTrailer.query.filter_by(is_deleted=False).count(),
        'jcl': JCL.query.filter_by(is_deleted=False).count(),
        'mail': Mail.query.filter_by(is_deleted=False).count(),
        'prm': PRM.query.filter_by(is_deleted=False).count(),
        'traducao': Traducao.query.filter_by(is_deleted=False).count(),
        'ser': SER.query.filter_by(is_deleted=False).count(),
    }

    # General counts
    general_counts = {
        'perfis': Perfil.query.filter_by(is_deleted=False).count(),
        'usuarios': User.query.count(),
        'faq': FAQ.query.filter_by(is_deleted=False).count(),
        'ftpusers': FTPUsers.query.filter_by(is_deleted=False).count(),
        'mailgroup': MailGroup.query.filter_by(is_deleted=False).count(),
        'roscoe': Roscoe.query.filter_by(is_deleted=False).count(),
    }

    # Audit counts
    audit_counts = {
        'audit_total': AuditLog.query.count(),
        'total_operacoes': AuditLog.query.count(),
        'audit_create': AuditLog.query.filter_by(operacao='CREATE').count(),
        'audit_update': AuditLog.query.filter_by(operacao='UPDATE').count(),
        'audit_delete': AuditLog.query.filter_by(operacao='DELETE').count(),
        'audit_restore': AuditLog.query.filter_by(operacao='RESTORE').count(),
        'audit_login': AuditLog.query.filter_by(operacao='LOGIN').count(),
    }

    return {**protocol_counts, **functionality_counts, **general_counts, **audit_counts}


def get_recent_activities(limit=20):
    """Get recent audit activities"""
    return AuditLog.query.order_by(AuditLog.data_hora.desc()).limit(limit).all()


def check_profile_dependencies(perfil_id):
    """Check if profile has dependent records"""
    from models import FTP, SCP, CD, HTTP, Jasppion, S3, MQ, CMD, Formato, HeaderTrailer, JCL, Mail, PRM, SER, Traducao

    dependencies = []
    models_to_check = [
        (FTP, 'FTP'), (SCP, 'SCP'), (CD, 'Connect:Direct'), 
        (HTTP, 'HTTP'), (Jasppion, 'JASPPION'), (S3, 'S3'), (MQ, 'MQ'),
        (CMD, 'CMD'), (Formato, 'Formato'), (HeaderTrailer, 'Header/Trailer'),
        (JCL, 'JCL'), (Mail, 'Mail'), (PRM, 'PRM'), 
        (Traducao, 'Tradução'), (SER, 'SER')
    ]

    for model, name in models_to_check:
        count = model.query.filter_by(id_perfil=perfil_id, is_deleted=False).count()
        if count > 0:
            dependencies.append(f"{name} ({count})")

    return dependencies


# Configuration management functions
def get_config_value(key, default=None):
    """Get a configuration value from the database"""
    from models import SystemConfig
    config = SystemConfig.query.filter_by(chave=key).first()
    return config.valor if config else default


def set_config_value(key, value, description=None):
    """Set a configuration value in the database"""
    from models import SystemConfig

    config = SystemConfig.query.filter_by(chave=key).first()
    if config:
        config.valor = value
        if description:
            config.descricao = description
        config.updated_at = datetime.utcnow()
    else:
        config = SystemConfig(
            chave=key,
            valor=value,
            descricao=description or f'Configuração {key}'
        )
        db.session.add(config)

    db.session.commit()
    return config


def get_database_configs():
    """Get Oracle database configuration values"""
    return {
        'oracle_host': get_config_value('oracle_host', 'ec2-52-202-108-33.compute-1.amazonaws.com'),
        'oracle_port': get_config_value('oracle_port', '1521'),
        'oracle_service': get_config_value('oracle_service', 'orcl'),
        'oracle_username': get_config_value('oracle_username', 'oracleuser'),
        'oracle_password': get_config_value('oracle_password', 'oracle'),
        'oracle_schema': get_config_value('oracle_schema', ''),
    }


def save_database_configs(config_data):
    """Save Oracle database configuration values"""
    configs = {
        'oracle_host': ('Oracle Host', config_data.get('oracle_host', '')),
        'oracle_port': ('Oracle Port', config_data.get('oracle_port', '')),
        'oracle_service': ('Oracle Service/SID', config_data.get('oracle_service', '')),
        'oracle_username': ('Oracle Username', config_data.get('oracle_username', '')),
        'oracle_password': ('Oracle Password', config_data.get('oracle_password', '')),
        'oracle_schema': ('Oracle Schema', config_data.get('oracle_schema', '')),
    }

    for key, (description, value) in configs.items():
        set_config_value(key, value, description)


def build_connection_strings():
    """Build connection string for Oracle"""
    configs = get_database_configs()

    oracle_conn_str = ""
    if configs['oracle_host'] and configs['oracle_service']:
        base_str = f"oracle+oracledb://{configs['oracle_username']}:{configs['oracle_password']}@{configs['oracle_host']}:{configs['oracle_port']}/{configs['oracle_service']}"
        oracle_conn_str = f"{base_str}?schema={configs['oracle_schema']}" if configs['oracle_schema'] else base_str

    return {'oracle': oracle_conn_str}


def get_server_configs():
    """Get all server configuration values"""
    bool_configs = ['maintenance_mode', 'debug_mode', 'auto_backup', 'smtp_use_tls']
    int_configs = ['max_upload_size', 'session_timeout', 'max_concurrent_users', 'log_retention_days', 'backup_retention', 'smtp_port']
    str_configs = ['server_name', 'server_description', 'log_level', 'backup_frequency', 'smtp_server', 'smtp_username', 'smtp_password', 'admin_email']

    defaults = {
        'server_name': 'Sistema de Transferência de Arquivos',
        'server_description': 'Sistema completo para controle de transferências',
        'log_level': 'INFO', 'backup_frequency': 'weekly',
        'max_upload_size': 16, 'session_timeout': 30, 'max_concurrent_users': 100,
        'log_retention_days': 30, 'backup_retention': 7, 'smtp_port': 587
    }

    configs = {}

    # Boolean configs
    for key in bool_configs:
        configs[key] = get_config_value(key, 'false').lower() == 'true'

    # Integer configs
    for key in int_configs:
        configs[key] = int(get_config_value(key, str(defaults.get(key, 0))))

    # String configs
    for key in str_configs:
        configs[key] = get_config_value(key, defaults.get(key, ''))

    return configs


def save_server_configs(config_data):
    """Save server configuration values"""
    config_mapping = {
        'server_name': 'Nome do Servidor',
        'server_description': 'Descrição do Servidor',
        'maintenance_mode': 'Modo de Manutenção',
        'debug_mode': 'Modo Debug',
        'max_upload_size': 'Tamanho Máximo de Upload (MB)',
        'session_timeout': 'Timeout de Sessão (minutos)',
        'max_concurrent_users': 'Máximo de Usuários Simultâneos',
        'log_level': 'Nível de Log',
        'log_retention_days': 'Retenção de Logs (dias)',
        'auto_backup': 'Backup Automático',
        'backup_frequency': 'Frequência do Backup',
        'backup_retention': 'Retenção de Backups (dias)',
        'smtp_server': 'Servidor SMTP',
        'smtp_port': 'Porta SMTP',
        'smtp_username': 'Usuário SMTP',
        'smtp_password': 'Senha SMTP',
        'smtp_use_tls': 'Usar TLS/SSL',
        'admin_email': 'Email do Administrador',
    }

    for key, description in config_mapping.items():
        value = config_data.get(key, '')
        if isinstance(value, bool):
            value = str(value).lower()
        elif isinstance(value, int):
            value = str(value)
        set_config_value(key, value, description)


def get_security_configs():
    """Get all security configuration values"""
    bool_configs = [
        'require_uppercase', 'require_lowercase', 'require_numbers', 'require_special_chars',
        'force_password_change', 'audit_login_success', 'audit_login_failure', 'audit_data_changes',
        'audit_file_operations', 'audit_configuration_changes', 'allow_concurrent_sessions',
        'block_suspicious_ips', 'secure_cookies', 'httponly_cookies', 'enable_csrf_protection',
        'rate_limiting', 'file_encryption'
    ]

    int_configs = [
        'min_password_length', 'password_expiry_days', 'max_login_attempts', 'account_lockout_duration',
        'max_requests_per_minute', 'encryption_key_rotation_days'
    ]

    str_configs = ['ip_whitelist', 'same_site_cookies', 'password_hash_algorithm']

    defaults = {
        'min_password_length': 8, 'password_expiry_days': 90, 'max_login_attempts': 5,
        'account_lockout_duration': 15, 'max_requests_per_minute': 60, 'encryption_key_rotation_days': 90,
        'same_site_cookies': 'Lax', 'password_hash_algorithm': 'pbkdf2'
    }

    configs = {}

    # Boolean configs (most default to true for security features)
    true_defaults = ['audit_login_success', 'audit_login_failure', 'audit_data_changes', 'audit_file_operations', 'audit_configuration_changes', 'allow_concurrent_sessions', 'secure_cookies', 'httponly_cookies', 'enable_csrf_protection']
    for key in bool_configs:
        default_val = 'true' if key in true_defaults else 'false'
        configs[key] = get_config_value(key, default_val).lower() == 'true'

    # Integer configs
    for key in int_configs:
        configs[key] = int(get_config_value(key, str(defaults.get(key, 0))))

    # String configs
    for key in str_configs:
        configs[key] = get_config_value(key, defaults.get(key, ''))

    return configs


def save_security_configs(config_data):
    """Save security configuration values"""
    config_mapping = {
        'min_password_length': 'Comprimento Mínimo da Senha',
        'require_uppercase': 'Exigir Letras Maiúsculas',
        'require_lowercase': 'Exigir Letras Minúsculas',
        'require_numbers': 'Exigir Números',
        'require_special_chars': 'Exigir Caracteres Especiais',
        'password_expiry_days': 'Expiração da Senha (dias)',
        'max_login_attempts': 'Tentativas Máximas de Login',
        'account_lockout_duration': 'Duração do Bloqueio (minutos)',
        'force_password_change': 'Forçar Troca de Senha no Primeiro Login',
        'audit_login_success': 'Registrar Logins Bem-sucedidos',
        'audit_login_failure': 'Registrar Tentativas de Login Falhadas',
        'audit_data_changes': 'Registrar Alterações de Dados',
        'audit_file_operations': 'Registrar Operações de Arquivo',
        'audit_configuration_changes': 'Registrar Mudanças de Configuração',
        'allow_concurrent_sessions': 'Permitir Sessões Simultâneas',
        'ip_whitelist': 'Lista de IPs Permitidos',
        'block_suspicious_ips': 'Bloquear IPs Suspeitos',
        'secure_cookies': 'Cookies Seguros (HTTPS)',
        'httponly_cookies': 'Cookies HTTPOnly',
        'same_site_cookies': 'SameSite Cookies',
        'enable_csrf_protection': 'Proteção CSRF',
        'rate_limiting': 'Limitação de Taxa',
        'max_requests_per_minute': 'Máximo de Requisições por Minuto',
        'password_hash_algorithm': 'Algoritmo de Hash da Senha',
        'file_encryption': 'Criptografia de Arquivos',
        'encryption_key_rotation_days': 'Rotação de Chaves (dias)',
    }

    for key, description in config_mapping.items():
        value = config_data.get(key, '')
        if isinstance(value, bool):
            value = str(value).lower()
        elif isinstance(value, int):
            value = str(value)
        set_config_value(key, value, description)


def save_config_values(config_dict):
    """Save multiple configuration values at once"""
    for key, value in config_dict.items():
        set_config_value(key, str(value), f'Configuração {key}')