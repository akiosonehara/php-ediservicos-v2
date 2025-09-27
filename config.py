# Sistema de Transferência de Arquivos v2.2.2
# Configuração centralizada da aplicação

# VERSÃO DA APLICAÇÃO - PONTO ÚNICO DE CONFIGURAÇÃO
VERSION = "v2.2.2"
APP_NAME = "Sistema de Transferência de Arquivos"
APP_FULL_NAME = f"{APP_NAME} {VERSION}"

# String de conexão Oracle - ÚNICO PONTO DE CONFIGURAÇÃO
ORACLE_DATABASE_URL = 'oracle+oracledb://oracleuser:oracle@ec2-52-202-108-33.compute-1.amazonaws.com:1521/orcl'

# Configurações do pool de conexões Oracle
ORACLE_ENGINE_OPTIONS = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
    'pool_size': 10,
    'max_overflow': 20
}

# Outras configurações da aplicação
SECRET_KEY = 'dev-secret-key-change-in-production'
UPLOAD_FOLDER = 'uploads'
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB