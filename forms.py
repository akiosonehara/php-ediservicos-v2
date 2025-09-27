from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, TextAreaField, BooleanField, IntegerField, SelectField, PasswordField, SubmitField, SelectMultipleField
from wtforms.validators import DataRequired, Length, Email, Optional, NumberRange

class LoginForm(FlaskForm):
    username = StringField('Usuário', validators=[DataRequired(), Length(1, 80)])
    password = PasswordField('Senha', validators=[DataRequired()])

class UserForm(FlaskForm):
    username = StringField('Usuário', validators=[DataRequired(), Length(1, 80)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Senha', validators=[Optional()])
    user_type = SelectField('Tipo de Usuário', choices=[('basico', 'Básico'), ('avancado', 'Avançado')])
    is_active = BooleanField('Ativo')

class PerfilForm(FlaskForm):
    perfil = StringField('Nome do Perfil', validators=[DataRequired(), Length(1, 60)])
    cad = StringField('CAD', validators=[Optional(), Length(max=150)])
    ass = StringField('ASS', validators=[Optional(), Length(max=150)])
    comentario = TextAreaField('Comentário', validators=[Optional(), Length(max=400)])

    # Protocol flags
    header_trailer = BooleanField('Header/Trailer')
    prm = BooleanField('PRM')
    formato = BooleanField('Formato')
    traducao = BooleanField('Tradução')
    scp = BooleanField('SCP')
    ftp = BooleanField('FTP')
    cd = BooleanField('Connect:Direct')
    cmd = BooleanField('CMD')
    jcl = BooleanField('JCL')
    ser = BooleanField('SER')
    mail = BooleanField('Mail')
    http = BooleanField('HTTP')
    jasppion = BooleanField('JASPPION')
    s3 = BooleanField('S3')
    mq = BooleanField('MQ')

    diagram = FileField('Diagrama', validators=[
        FileAllowed(['pdf', 'png', 'jpg', 'jpeg'], 'Apenas arquivos PDF, PNG ou JPEG são permitidos!')
    ])

class FTPForm(FlaskForm):
    perfil_id = SelectField('Perfil', coerce=int, validators=[DataRequired()], choices=[])
    zip = BooleanField('ZIP')
    crlf = BooleanField('CRLF')
    rel = BooleanField('REL')
    bin = BooleanField('BIN')
    def_flag = BooleanField('DEF')
    servidor = StringField('Servidor', validators=[Optional(), Length(max=80)])
    porta = IntegerField('Porta', validators=[Optional(), NumberRange(min=1, max=65535)], default=21)
    usuario = StringField('Usuário', validators=[Optional(), Length(max=80)])
    q_site = StringField('Q_SITE', validators=[Optional(), Length(max=200)])
    comando = SelectField('Comando', choices=[('', 'Selecione...'), ('PUT', 'PUT'), ('GET', 'GET')], validators=[Optional()])
    cdup = BooleanField('CDUP', default=True)
    dir_local = StringField('Diretório Local', validators=[Optional(), Length(max=100)])
    dir_remoto = StringField('Diretório Remoto', validators=[Optional(), Length(max=100)])
    arquivo_local = StringField('Arquivo Local', validators=[Optional(), Length(max=100)])
    arquivo_remoto = StringField('Arquivo Remoto', validators=[Optional(), Length(max=100)])
    dmz = BooleanField('DMZ')
    cert = StringField('Certificado', validators=[Optional(), Length(max=60)])
    code = BooleanField('CODE')
    mail = BooleanField('Email')
    mailmsg = TextAreaField('Mensagem do Email', validators=[Optional(), Length(max=2000)])
    mailass = StringField('Assunto do Email', validators=[Optional(), Length(max=200)])
    maildest = TextAreaField('Destinatários do Email', validators=[Optional(), Length(max=1000)])
    mailanexo = BooleanField('Enviar como Anexo')
    maildest = TextAreaField('Destinatários', validators=[Optional(), Length(max=1000)])
    mailanexo = BooleanField('Incluir Anexo')

class SCPForm(FlaskForm):
    perfil_id = SelectField('Perfil', coerce=int, validators=[DataRequired()], choices=[])
    zip = BooleanField('ZIP')
    crlf = BooleanField('CRLF')
    rel = BooleanField('REL')
    bin = BooleanField('BIN')
    usuario = StringField('Usuário', validators=[Optional(), Length(max=80)])
    senha = StringField('Senha', validators=[Optional(), Length(max=40)])
    servidor = StringField('Servidor', validators=[Optional(), Length(max=80)])
    porta = IntegerField('Porta', validators=[Optional(), NumberRange(min=1, max=65535)], default=22)
    comando = SelectField('Comando', choices=[('', 'Selecione...'), ('PUT', 'PUT'), ('GET', 'GET')], validators=[Optional()])
    dir_local = StringField('Diretório Local', validators=[Optional(), Length(max=100)])
    dir_remoto = StringField('Diretório Remoto', validators=[Optional(), Length(max=200)])
    arquivo_local = StringField('Arquivo Local', validators=[Optional(), Length(max=100)])
    arquivo_remoto = StringField('Arquivo Remoto', validators=[Optional(), Length(max=100)])
    ssh = StringField('SSH', validators=[Optional(), Length(max=400)])
    ok = StringField('OK', validators=[Optional(), Length(max=800)])
    nok = StringField('NOK', validators=[Optional(), Length(max=800)])
    tel = StringField('TEL', validators=[Optional(), Length(max=40)])
    pri = IntegerField('PRI', validators=[Optional()])
    dmz = BooleanField('DMZ')
    code = BooleanField('CODE')
    mail = BooleanField('Email')
    mailmsg = TextAreaField('Mensagem do Email', validators=[Optional(), Length(max=2000)])
    mailass = StringField('Assunto do Email', validators=[Optional(), Length(max=200)])
    maildest = TextAreaField('Destinatários', validators=[Optional(), Length(max=1000)])
    mailanexo = BooleanField('Incluir Anexo')

class HTTPForm(FlaskForm):
    perfil_id = SelectField('Perfil', coerce=int, validators=[DataRequired()], choices=[])
    dns = StringField('DNS', validators=[Optional(), Length(max=80)])
    porta = StringField('Porta', validators=[Optional(), Length(max=10)])
    uri = StringField('URI', validators=[Optional(), Length(max=80)])
    metodo = SelectField('Método', choices=[('GET', 'GET'), ('POST', 'POST'), ('PUT', 'PUT'), ('DELETE', 'DELETE')], validators=[Optional()])
    prms = StringField('Parâmetros', validators=[Optional(), Length(max=240)])
    hash = StringField('Hash', validators=[Optional(), Length(max=40)])
    tipo_arq = StringField('Tipo de Arquivo', validators=[Optional(), Length(max=40)])
    cert = StringField('Certificado', validators=[Optional(), Length(max=100)])
    json = TextAreaField('JSON', validators=[Optional(), Length(max=1000)])
    usuario = StringField('Usuário', validators=[Optional(), Length(max=80)])
    dmz = BooleanField('DMZ')
    mail = BooleanField('Email')
    mailmsg = TextAreaField('Mensagem do Email', validators=[Optional(), Length(max=2000)])
    mailass = StringField('Assunto do Email', validators=[Optional(), Length(max=200)])
    maildest = TextAreaField('Destinatários', validators=[Optional(), Length(max=1000)])
    mailanexo = BooleanField('Incluir Anexo')

class S3Form(FlaskForm):
    perfil_id = SelectField('Perfil', coerce=int, validators=[DataRequired()], choices=[])
    endpointurl = StringField('Endpoint URL', validators=[Optional(), Length(max=100)])
    endpointport = StringField('Porta do Endpoint', validators=[Optional(), Length(max=10)])
    bucketname = StringField('Nome do Bucket', validators=[Optional(), Length(max=100)])
    action = SelectField('Ação', choices=[('GET', 'GET'), ('PUT', 'PUT'), ('DELETE', 'DELETE')], validators=[Optional()])
    accesskey = StringField('Access Key', validators=[Optional(), Length(max=256)])
    secretkey = StringField('Secret Key', validators=[Optional(), Length(max=256)])
    foldername = StringField('Nome da Pasta', validators=[Optional(), Length(max=100)])
    filename = StringField('Nome do Arquivo', validators=[Optional(), Length(max=100)])
    localfilename = StringField('Nome do Arquivo Local', validators=[Optional(), Length(max=100)])
    header = TextAreaField('Header', validators=[Optional(), Length(max=2000)])
    acl = TextAreaField('ACL', validators=[Optional(), Length(max=2000)])
    tag = TextAreaField('Tag', validators=[Optional(), Length(max=2000)])
    ecs = TextAreaField('ECS', validators=[Optional(), Length(max=2000)])
    region = StringField('Região', validators=[Optional(), Length(max=100)])
    dmz = BooleanField('DMZ')
    mail = BooleanField('Email')
    mailmsg = TextAreaField('Mensagem do Email', validators=[Optional(), Length(max=2000)])
    mailass = StringField('Assunto do Email', validators=[Optional(), Length(max=200)])
    maildest = TextAreaField('Destinatários', validators=[Optional(), Length(max=1000)])
    mailanexo = BooleanField('Incluir Anexo')

class JasppionForm(FlaskForm):
    perfil_id = SelectField('Perfil', coerce=int, validators=[DataRequired()], choices=[])
    servidor = StringField('Servidor', validators=[Optional(), Length(max=80)])
    porta = StringField('Porta', validators=[Optional(), Length(max=10)])
    uri = StringField('URI', validators=[Optional(), Length(max=80)])
    app = StringField('App', validators=[Optional(), Length(max=4)])
    fsadabas = StringField('FS Adabas', validators=[Optional(), Length(max=4)])
    logon = StringField('Logon', validators=[Optional(), Length(max=10)])
    programa = StringField('Programa', validators=[Optional(), Length(max=8)])
    roscoe = StringField('Roscoe', validators=[Optional(), Length(max=10)])
    rcode = StringField('R Code', validators=[Optional(), Length(max=4)])
    delimitador = StringField('Delimitador', validators=[Optional(), Length(max=60)])
    mail = BooleanField('Email')
    mailmsg = TextAreaField('Mensagem do Email', validators=[Optional(), Length(max=2000)])
    mailass = StringField('Assunto do Email', validators=[Optional(), Length(max=200)])
    maildest = TextAreaField('Destinatários', validators=[Optional(), Length(max=1000)])
    mailanexo = BooleanField('Incluir Anexo')

class CDForm(FlaskForm):
    perfil_id = SelectField('Perfil', coerce=int, validators=[DataRequired()], choices=[])
    aut = StringField('Autorização', validators=[Optional(), Length(max=60)])
    dhd = StringField('DHD', validators=[Optional(), Length(max=20)])
    dst = TextAreaField('DST', validators=[Optional(), Length(max=800)])
    tit = StringField('Título', validators=[Optional(), Length(max=240)])
    dsn = TextAreaField('DSN', validators=[Optional(), Length(max=800)])
    dcb = TextAreaField('DCB', validators=[Optional(), Length(max=800)])
    codbanco = StringField('Código do Banco', validators=[Optional(), Length(max=60)])
    node = TextAreaField('Node', validators=[Optional(), Length(max=400)])
    tsk = StringField('Task', validators=[Optional(), Length(max=240)])
    job = StringField('Job', validators=[Optional(), Length(max=240)])
    spc = StringField('SPC', validators=[Optional(), Length(max=100)])
    disp = StringField('Disposição', validators=[Optional(), Length(max=60)])
    sysopts = TextAreaField('System Options', validators=[Optional(), Length(max=800)])
    opts = TextAreaField('Options', validators=[Optional(), Length(max=800)])
    dmz = BooleanField('DMZ', default=True)
    mail = BooleanField('Email')
    mailmsg = TextAreaField('Mensagem do Email', validators=[Optional(), Length(max=2000)])
    mailass = StringField('Assunto do Email', validators=[Optional(), Length(max=200)])
    maildest = TextAreaField('Destinatários', validators=[Optional(), Length(max=1000)])
    mailanexo = BooleanField('Incluir Anexo')

class MQForm(FlaskForm):
    perfil_id = SelectField('Perfil', coerce=int, validators=[DataRequired()], choices=[])
    hostname = StringField('Hostname', validators=[DataRequired(), Length(max=100)])
    port = IntegerField('Porta', validators=[DataRequired(), NumberRange(min=1, max=65535)])
    channel = StringField('Channel', validators=[DataRequired(), Length(max=100)])
    userid = StringField('User ID', validators=[DataRequired(), Length(max=100)])
    passwd = StringField('Password', validators=[Optional(), Length(max=100)])
    qmgr = StringField('Queue Manager', validators=[Optional(), Length(max=100)])
    qname = StringField('Queue Name', validators=[Optional(), Length(max=100)])
    action = SelectField('Action', choices=[('GET', 'GET'), ('PUT', 'PUT')], validators=[Optional()])
    gettype = SelectField('Get Type', choices=[('BROWSE', 'BROWSE'), ('DESTRUCTIVE', 'DESTRUCTIVE')], validators=[Optional()])
    msgtype = SelectField('Message Type', choices=[('REQUEST', 'REQUEST'), ('REPLY', 'REPLY')], validators=[Optional()])
    msgid = StringField('Message ID', validators=[Optional(), Length(max=20)])
    ccsid = StringField('CCSID', validators=[Optional(), Length(max=20)])
    ttl = IntegerField('TTL', validators=[Optional(), NumberRange(min=0)])
    ssl = BooleanField('SSL')
    tls = StringField('TLS', validators=[Optional(), Length(max=20)])
    cert = StringField('Certificate', validators=[Optional(), Length(max=100)])
    mail = BooleanField('Mail')
    mailass = StringField('Mail Subject', validators=[Optional(), Length(max=200)])
    maildest = TextAreaField('Mail Destinations', validators=[Optional(), Length(max=1000)])
    mailmsg = TextAreaField('Mail Message', validators=[Optional(), Length(max=2000)])
    mailanexo = BooleanField('Mail Attachment')

# Funcionalidades Forms
class CMDForm(FlaskForm):
    perfil_id = SelectField('Perfil', coerce=int, validators=[DataRequired()], choices=[])
    comando = TextAreaField('Comando', validators=[Optional(), Length(max=400)])

class FormatoForm(FlaskForm):
    perfil_id = SelectField('Perfil', coerce=int, validators=[DataRequired()], choices=[])
    de = StringField('De', validators=[Optional(), Length(max=40)])
    para = StringField('Para', validators=[Optional(), Length(max=40)])

class HeaderTrailerForm(FlaskForm):
    perfil_id = SelectField('Perfil', coerce=int, validators=[DataRequired()], choices=[])
    htr0_p1 = StringField('HTR0 P1', validators=[Optional(), Length(max=20)])
    htr0_p2 = StringField('HTR0 P2', validators=[Optional(), Length(max=20)])
    htr1_p1 = IntegerField('HTR1 P1', validators=[Optional()])
    htr1_p2 = BooleanField('HTR1 P2')
    htr2 = BooleanField('HTR2')
    htr3 = StringField('HTR3', validators=[Optional(), Length(max=20)])
    htr4 = StringField('HTR4', validators=[Optional(), Length(max=20)])
    htr5 = BooleanField('HTR5')
    htr6 = BooleanField('HTR6')
    htr7 = BooleanField('HTR7')
    htr8_p1 = TextAreaField('HTR8 P1', validators=[Optional(), Length(max=400)])
    htr8_p2 = BooleanField('HTR8 P2')
    htr9_p1 = StringField('HTR9 P1', validators=[Optional(), Length(max=20)])
    htr9_p2 = StringField('HTR9 P2', validators=[Optional(), Length(max=20)])
    htra = StringField('HTRA', validators=[Optional(), Length(max=20)])

class JCLForm(FlaskForm):
    perfil_id = SelectField('Perfil', coerce=int, validators=[DataRequired()], choices=[])
    servidor = StringField('Servidor', validators=[Optional(), Length(max=80)])
    usuario = StringField('Usuário', validators=[Optional(), Length(max=80)])
    jcl = TextAreaField('JCL', validators=[Optional(), Length(max=900)])
    dmz = BooleanField('DMZ')

class MailForm(FlaskForm):
    perfil_id = SelectField('Perfil', coerce=int, validators=[DataRequired()], choices=[])
    msg = TextAreaField('Mensagem', validators=[Optional(), Length(max=2000)])
    tit = StringField('Título', validators=[Optional(), Length(max=200)])
    dest = TextAreaField('Destinatários', validators=[Optional(), Length(max=1000)])
    anexo = StringField('Anexo', validators=[Optional(), Length(max=50)])

class PRMForm(FlaskForm):
    perfil_id = SelectField('Perfil', coerce=int, validators=[DataRequired()], choices=[])
    # Variáveis V0-V9
    v0 = StringField('V0', validators=[Optional(), Length(max=20)])
    v1 = StringField('V1', validators=[Optional(), Length(max=20)])
    v2 = StringField('V2', validators=[Optional(), Length(max=20)])
    v3 = StringField('V3', validators=[Optional(), Length(max=20)])
    v4 = StringField('V4', validators=[Optional(), Length(max=20)])
    v5 = StringField('V5', validators=[Optional(), Length(max=20)])
    v6 = StringField('V6', validators=[Optional(), Length(max=20)])
    v7 = StringField('V7', validators=[Optional(), Length(max=20)])
    v8 = StringField('V8', validators=[Optional(), Length(max=20)])
    v9 = StringField('V9', validators=[Optional(), Length(max=20)])
    # Números N0-N9
    n0 = StringField('N0', validators=[Optional(), Length(max=20)])
    n1 = StringField('N1', validators=[Optional(), Length(max=20)])
    n2 = StringField('N2', validators=[Optional(), Length(max=20)])
    n3 = StringField('N3', validators=[Optional(), Length(max=20)])
    n4 = StringField('N4', validators=[Optional(), Length(max=20)])
    n5 = StringField('N5', validators=[Optional(), Length(max=20)])
    n6 = StringField('N6', validators=[Optional(), Length(max=20)])
    n7 = StringField('N7', validators=[Optional(), Length(max=20)])
    n8 = StringField('N8', validators=[Optional(), Length(max=20)])
    n9 = StringField('N9', validators=[Optional(), Length(max=20)])
    # Flags booleanos
    bpid = BooleanField('BPID')
    dd = BooleanField('DD')
    dsu = BooleanField('DSU')
    dsl = BooleanField('DSL')
    dru = BooleanField('DRU')
    drl = BooleanField('DRL')
    mm = BooleanField('MM')
    mru = BooleanField('MRU')
    mrl = BooleanField('MRL')
    msu = BooleanField('MSU')
    msl = BooleanField('MSL')
    aal = BooleanField('AAL')
    aau = BooleanField('AAU')

class TraducaoForm(FlaskForm):
    perfil_id = SelectField('Perfil', coerce=int, validators=[DataRequired()], choices=[])
    de = StringField('De', validators=[Optional(), Length(max=100)])
    para = StringField('Para', validators=[Optional(), Length(max=100)])
    descricao = TextAreaField('Descrição', validators=[Optional(), Length(max=400)])

class SERForm(FlaskForm):
    perfil_id = SelectField('Perfil', coerce=int, validators=[DataRequired()], choices=[])
    tit = StringField('Título', validators=[Optional(), Length(max=200)])
    arquivo = StringField('Arquivo', validators=[Optional(), Length(max=100)])
    rel = BooleanField('REL')
    mailc = BooleanField('MAILC')
    def_flag = BooleanField('DEF')
    zip = BooleanField('ZIP')
    crlf = BooleanField('CRLF')
    msgsrg_env = BooleanField('MSGSRG_ENV')

# Formulários para Notificações
class FTPUsersForm(FlaskForm):
    usuario = StringField('Usuário', validators=[DataRequired(), Length(1, 100)])
    senha = StringField('Senha', validators=[Optional(), Length(max=80)])
    mf_unit = StringField('MF Unit', validators=[Optional(), Length(max=20)])

class MailGroupForm(FlaskForm):
    grupo = StringField('Grupo', validators=[DataRequired(), Length(1, 60)])
    dst = TextAreaField('Destinatários', validators=[Optional(), Length(max=1000)])

class RoscoeForm(FlaskForm):
    chave = StringField('Chave', validators=[DataRequired(), Length(1, 10)])
    dst = TextAreaField('Destinatários', validators=[Optional(), Length(max=1000)])

class FAQForm(FlaskForm):
    categoria = StringField('Categoria', validators=[DataRequired(), Length(1, 100)])
    pergunta = StringField('Pergunta', validators=[DataRequired(), Length(1, 500)])
    resposta = TextAreaField('Resposta', validators=[DataRequired()])
    imagem = FileField('Imagem', validators=[
        FileAllowed(['png', 'jpg', 'jpeg', 'gif'], 'Apenas arquivos de imagem são permitidos!')
    ])

class DatabaseConfigForm(FlaskForm):
    # Oracle Configuration
    oracle_host = StringField('Oracle Host', validators=[Optional(), Length(max=255)], 
                              render_kw={'placeholder': 'ec2-52-202-108-33.compute-1.amazonaws.com'})
    oracle_port = StringField('Oracle Porta', validators=[Optional(), Length(max=10)], 
                              render_kw={'placeholder': '1521'})
    oracle_service = StringField('Oracle Service Name', validators=[Optional(), Length(max=100)], 
                                 render_kw={'placeholder': 'orcl'})
    oracle_username = StringField('Oracle Usuário', validators=[Optional(), Length(max=100)], 
                                  render_kw={'placeholder': 'oracleuser'})
    oracle_password = PasswordField('Oracle Senha', validators=[Optional()], 
                                    render_kw={'placeholder': 'Senha do Oracle'})
    oracle_schema = StringField('Oracle Schema (Opcional)', validators=[Optional(), Length(max=100)], 
                                render_kw={'placeholder': 'Schema padrão'})
    
    submit = SubmitField('Salvar Configurações')

class ServerConfigForm(FlaskForm):
    # Configurações Gerais do Servidor
    server_name = StringField('Nome do Servidor', validators=[Optional(), Length(max=100)], 
                              render_kw={'placeholder': 'Sistema de Transferência'})
    server_description = TextAreaField('Descrição do Servidor', validators=[Optional(), Length(max=500)])
    maintenance_mode = BooleanField('Modo de Manutenção')
    debug_mode = BooleanField('Modo Debug')

    # Configurações de Performance
    max_upload_size = IntegerField('Tamanho Máximo de Upload (MB)', validators=[Optional(), NumberRange(min=1, max=1024)], 
                                   render_kw={'placeholder': '16'})
    session_timeout = IntegerField('Timeout de Sessão (minutos)', validators=[Optional(), NumberRange(min=1, max=1440)], 
                                   render_kw={'placeholder': '30'})
    max_concurrent_users = IntegerField('Máximo de Usuários Simultâneos', validators=[Optional(), NumberRange(min=1, max=1000)], 
                                        render_kw={'placeholder': '100'})

    # Configurações de Log
    log_level = SelectField('Nível de Log', 
                           choices=[('DEBUG', 'Debug'), ('INFO', 'Info'), ('WARNING', 'Warning'), ('ERROR', 'Error')],
                           validators=[Optional()])
    log_retention_days = IntegerField('Retenção de Logs (dias)', validators=[Optional(), NumberRange(min=1, max=365)], 
                                      render_kw={'placeholder': '30'})

    # Configurações de Backup
    auto_backup = BooleanField('Backup Automático')
    backup_frequency = SelectField('Frequência do Backup', 
                                  choices=[('daily', 'Diário'), ('weekly', 'Semanal'), ('monthly', 'Mensal')],
                                  validators=[Optional()])
    backup_retention = IntegerField('Retenção de Backups (dias)', validators=[Optional(), NumberRange(min=1, max=90)], 
                                   render_kw={'placeholder': '7'})

    # Configurações de Email
    smtp_server = StringField('Servidor SMTP', validators=[Optional(), Length(max=255)])
    smtp_port = IntegerField('Porta SMTP', validators=[Optional(), NumberRange(min=1, max=65535)], 
                            render_kw={'placeholder': '587'})
    smtp_username = StringField('Usuário SMTP', validators=[Optional(), Length(max=100)])
    smtp_password = PasswordField('Senha SMTP', validators=[Optional(), Length(max=255)])
    smtp_use_tls = BooleanField('Usar TLS/SSL')
    admin_email = StringField('Email do Administrador', validators=[Optional(), Email(), Length(max=255)])

    submit = SubmitField('Salvar Configurações do Servidor')

class SecurityConfigForm(FlaskForm):
    # Políticas de Senha
    min_password_length = IntegerField('Comprimento Mínimo da Senha', validators=[Optional(), NumberRange(min=4, max=128)], 
                                      render_kw={'placeholder': '8'})
    require_uppercase = BooleanField('Exigir Letras Maiúsculas')
    require_lowercase = BooleanField('Exigir Letras Minúsculas')
    require_numbers = BooleanField('Exigir Números')
    require_special_chars = BooleanField('Exigir Caracteres Especiais')
    password_expiry_days = IntegerField('Expiração da Senha (dias)', validators=[Optional(), NumberRange(min=0, max=365)], 
                                       render_kw={'placeholder': '90 (0 = nunca expira)'})

    # Configurações de Login
    max_login_attempts = IntegerField('Tentativas Máximas de Login', validators=[Optional(), NumberRange(min=1, max=10)], 
                                     render_kw={'placeholder': '5'})
    account_lockout_duration = IntegerField('Duração do Bloqueio (minutos)', validators=[Optional(), NumberRange(min=1, max=1440)], 
                                           render_kw={'placeholder': '15'})
    force_password_change = BooleanField('Forçar Troca de Senha no Primeiro Login')

    # Histórico de Alterações e Monitoramento
    audit_login_success = BooleanField('Registrar Logins Bem-sucedidos', default=True)
    audit_login_failure = BooleanField('Registrar Tentativas de Login Falhadas', default=True)
    audit_data_changes = BooleanField('Registrar Alterações de Dados', default=True)
    audit_file_operations = BooleanField('Registrar Operações de Arquivo', default=True)
    audit_configuration_changes = BooleanField('Registrar Mudanças de Configuração', default=True)

    # Controle de Acesso
    allow_concurrent_sessions = BooleanField('Permitir Sessões Simultâneas')
    ip_whitelist = TextAreaField('Lista de IPs Permitidos', validators=[Optional(), Length(max=2000)],
                                render_kw={'placeholder': '192.168.1.1\n10.0.0.0/24\nUm IP por linha'})
    block_suspicious_ips = BooleanField('Bloquear IPs Suspeitos')

    # Configurações de Sessão
    secure_cookies = BooleanField('Cookies Seguros (HTTPS)', default=True)
    httponly_cookies = BooleanField('Cookies HTTPOnly', default=True)
    same_site_cookies = SelectField('SameSite Cookies', 
                                   choices=[('Strict', 'Strict'), ('Lax', 'Lax'), ('None', 'None')],
                                   default='Lax')

    # Proteção contra Ataques
    enable_csrf_protection = BooleanField('Proteção CSRF', default=True)
    rate_limiting = BooleanField('Limitação de Taxa (Rate Limiting)')
    max_requests_per_minute = IntegerField('Máximo de Requisições por Minuto', validators=[Optional(), NumberRange(min=1, max=1000)], 
                                          render_kw={'placeholder': '60'})

    # Criptografia e Hashing
    password_hash_algorithm = SelectField('Algoritmo de Hash da Senha', 
                                         choices=[('pbkdf2', 'PBKDF2'), ('bcrypt', 'bcrypt'), ('scrypt', 'scrypt')],
                                         default='pbkdf2')
    file_encryption = BooleanField('Criptografia de Arquivos')
    encryption_key_rotation_days = IntegerField('Rotação de Chaves (dias)', validators=[Optional(), NumberRange(min=30, max=365)], 
                                               render_kw={'placeholder': '90'})

    submit = SubmitField('Salvar Configurações de Segurança')


class LDAPConfigForm(FlaskForm):
    """Formulário para configuração de autenticação LDAP"""

    # Configurações Básicas
    ldap_enabled = BooleanField('Habilitar Autenticação LDAP')
    ldap_server_uri = StringField('URI do Servidor LDAP', validators=[Optional(), Length(max=200)],
                                 render_kw={'placeholder': 'ldap://servidor.exemplo.com:389 ou ldaps://servidor.exemplo.com:636'})
    ldap_base_dn = StringField('Base DN', validators=[Optional(), Length(max=200)],
                              render_kw={'placeholder': 'dc=exemplo,dc=com'})

    # Configurações de Bind (Opcionais)
    ldap_bind_dn = StringField('Bind DN (Opcional)', validators=[Optional(), Length(max=200)],
                              render_kw={'placeholder': 'cn=admin,dc=exemplo,dc=com'})
    ldap_bind_password = PasswordField('Senha do Bind DN', validators=[Optional(), Length(max=100)],
                                      render_kw={'placeholder': 'Senha do usuário administrativo'})

    # Configurações de Busca de Usuários
    ldap_user_search_filter = StringField('Filtro de Busca de Usuário', validators=[Optional(), Length(max=200)],
                                         render_kw={'placeholder': '(cn={username})'}, 
                                         default='(cn={username})')
    ldap_user_dn_template = StringField('Template DN do Usuário', validators=[Optional(), Length(max=200)],
                                       render_kw={'placeholder': 'cn={username},{base_dn}'}, 
                                       default='cn={username},{base_dn}')

    # Configurações de Grupos
    ldap_group_search_base = StringField('Base DN dos Grupos (Opcional)', validators=[Optional(), Length(max=200)],
                                        render_kw={'placeholder': 'ou=groups,dc=exemplo,dc=com'})
    ldap_group_search_filter = StringField('Filtro de Busca de Grupos', validators=[Optional(), Length(max=200)],
                                          render_kw={'placeholder': '(member={user_dn})'}, 
                                          default='(member={user_dn})')
    ldap_admin_groups = TextAreaField('Grupos de Administrador', validators=[Optional(), Length(max=500)],
                                     render_kw={'placeholder': 'cn=admins,ou=groups,dc=exemplo,dc=com\ncn=system-admins,ou=groups,dc=exemplo,dc=com\nUm grupo por linha'})

    # Configurações de Mapeamento
    ldap_email_attribute = StringField('Atributo de Email', validators=[Optional(), Length(max=50)],
                                      render_kw={'placeholder': 'mail'}, default='mail')
    ldap_name_attribute = StringField('Atributo de Nome', validators=[Optional(), Length(max=50)],
                                     render_kw={'placeholder': 'cn'}, default='cn')

    # Configurações de Timeout e Conexão
    ldap_timeout = IntegerField('Timeout de Conexão (segundos)', validators=[Optional(), NumberRange(min=5, max=120)],
                               render_kw={'placeholder': '10'}, default=10)
    ldap_auto_create_users = BooleanField('Criar Automaticamente Usuários LDAP', default=True)
    ldap_sync_groups = BooleanField('Sincronizar Grupos LDAP', default=True)

    submit = SubmitField('Salvar Configurações LDAP')

class AdvancedSearchForm(FlaskForm):
    search_term = StringField('Termo de Busca', 
                             validators=[DataRequired(), Length(min=2, max=200)],
                             render_kw={'placeholder': 'Digite o termo a ser buscado...'})
    submit = SubmitField('Buscar')