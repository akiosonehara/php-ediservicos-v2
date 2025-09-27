from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import synonym
from app import db


class User(UserMixin, db.Model):
    __tablename__ = 'usuarios'

    id = db.Column(db.Integer, db.Sequence('usuarios_id_seq'), primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    user_type = db.Column(db.String(20), default='basico')
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    auth_type = db.Column(db.String(20), default='local')
    ldap_dn = db.Column(db.String(500))
    ldap_groups = db.Column(db.Text)

    def set_password(self, password):
        if self.auth_type == 'local':
            self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')

    def check_password(self, password):
        return self.auth_type == 'local' and self.password_hash and check_password_hash(self.password_hash, password)

    def is_ldap_user(self):
        return self.auth_type == 'ldap'

    def is_local_user(self):
        return self.auth_type == 'local'

    def is_advanced(self):
        return self.user_type == 'avancado' or self.user_type == 'admin'


class Perfil(db.Model):
    __tablename__ = 'tb_perfil'

    id_perfil = db.Column(db.Integer, db.Sequence('tb_perfil_id_perfil_seq'), primary_key=True)
    perfil = db.Column(db.String(60), nullable=False, unique=True)
    cad = db.Column(db.String(150))
    ass = db.Column(db.String(150))
    comentario = db.Column(db.String(400))

    # Protocol flags
    header_trailer = db.Column(db.Boolean, default=False)
    prm = db.Column(db.Boolean, default=False)
    formato = db.Column(db.Boolean, default=False)
    traducao = db.Column(db.Boolean, default=False)
    scp = db.Column(db.Boolean, default=False)
    ftp = db.Column(db.Boolean, default=False)
    cd = db.Column(db.Boolean, default=False)
    cmd = db.Column(db.Boolean, default=False)
    jcl = db.Column(db.Boolean, default=False)
    ser = db.Column(db.Boolean, default=False)
    mail = db.Column(db.Boolean, default=False)
    http = db.Column(db.Boolean, default=False)
    jasppion = db.Column(db.Boolean, default=False)
    s3 = db.Column(db.Boolean, default=False)
    mq = db.Column(db.Boolean, default=False)

    diagram_filename = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_deleted = db.Column(db.Boolean, default=False)


# Base class for protocol configurations
class BaseProtocol:
    id_perfil = db.Column(db.Integer, db.ForeignKey('tb_perfil.id_perfil'), nullable=False)
    is_deleted = db.Column(db.Boolean, default=False)
    # Email fields (common to most protocols)
    mail = db.Column(db.Boolean, default=False)
    mailmsg = db.Column(db.String(2000))
    mailass = db.Column(db.String(200))
    maildest = db.Column(db.String(1000))
    mailanexo = db.Column(db.Boolean, default=False)


class FTP(db.Model, BaseProtocol):
    __tablename__ = 'tb_ftp'

    id_ftp = db.Column(db.Integer, db.Sequence('tb_ftp_id_ftp_seq'), primary_key=True)
    servidor = db.Column(db.String(80))
    porta = db.Column(db.Integer, default=21)
    usuario = db.Column(db.String(80))
    q_site = db.Column(db.String(200))
    comando = db.Column(db.String(20))
    dir_local = db.Column(db.String(100))
    dir_remoto = db.Column(db.String(100))
    arquivo_local = db.Column(db.String(100))
    arquivo_remoto = db.Column(db.String(100))
    cert = db.Column(db.String(60))

    # Boolean flags
    zip = db.Column(db.Boolean, default=False)
    crlf = db.Column(db.Boolean, default=False)
    rel = db.Column(db.Boolean, default=False)
    bin = db.Column(db.Boolean, default=False)
    def_flag = db.Column('def', db.Boolean, default=False)
    cdup = db.Column(db.Boolean, default=True)
    dmz = db.Column(db.Boolean, default=False)
    code = db.Column(db.Boolean, default=False)

    perfil = db.relationship('Perfil', backref='ftp_configs')


# Add synonym to allow using 'def' as field name
setattr(FTP, 'def', synonym('def_flag'))


class SCP(db.Model, BaseProtocol):
    __tablename__ = 'tb_scp'

    id_scp = db.Column(db.Integer, db.Sequence('tb_scp_id_scp_seq'), primary_key=True)
    servidor = db.Column(db.String(80))
    porta = db.Column(db.Integer, default=22)
    usuario = db.Column(db.String(80))
    senha = db.Column(db.String(40))
    comando = db.Column(db.String(20))
    dir_local = db.Column(db.String(100))
    dir_remoto = db.Column(db.String(200))
    arquivo_local = db.Column(db.String(100))
    arquivo_remoto = db.Column(db.String(100))
    ssh = db.Column(db.String(400))
    ok = db.Column(db.String(800))
    nok = db.Column(db.String(800))
    tel = db.Column(db.String(40))
    pri = db.Column(db.Integer)

    # Boolean flags
    zip = db.Column(db.Boolean, default=False)
    crlf = db.Column(db.Boolean, default=False)
    rel = db.Column(db.Boolean, default=False)
    bin = db.Column(db.Boolean, default=False)
    dmz = db.Column(db.Boolean, default=False)
    code = db.Column(db.Boolean, default=False)

    perfil = db.relationship('Perfil', backref='scp_configs')


class HTTP(db.Model, BaseProtocol):
    __tablename__ = 'tb_http'

    id_http = db.Column(db.Integer, db.Sequence('tb_http_id_http_seq'), primary_key=True)
    dns = db.Column(db.String(80))
    porta = db.Column(db.String(10))
    uri = db.Column(db.String(80))
    metodo = db.Column(db.String(20))
    prms = db.Column(db.String(240))
    hash = db.Column(db.String(40))
    tipo_arq = db.Column(db.String(40))
    cert = db.Column(db.String(100))
    json = db.Column(db.String(1000))
    usuario = db.Column(db.String(80))
    dmz = db.Column(db.Boolean, default=False)

    perfil = db.relationship('Perfil', backref='http_configs')


class S3(db.Model, BaseProtocol):
    __tablename__ = 'tb_s3'

    id_s3 = db.Column(db.Integer, db.Sequence('tb_s3_id_s3_seq'), primary_key=True)
    endpointurl = db.Column(db.String(100))
    endpointport = db.Column(db.String(10))
    bucketname = db.Column(db.String(100))
    action = db.Column(db.String(10))
    accesskey = db.Column(db.String(256))
    secretkey = db.Column(db.String(256))
    foldername = db.Column(db.String(100))
    filename = db.Column(db.String(100))
    localfilename = db.Column(db.String(100))
    header = db.Column(db.String(2000))
    acl = db.Column(db.String(2000))
    tag = db.Column(db.String(2000))
    ecs = db.Column(db.String(2000))
    region = db.Column(db.String(100))
    dmz = db.Column(db.Boolean, default=False)

    perfil = db.relationship('Perfil', backref='s3_configs')


class MQ(db.Model, BaseProtocol):
    __tablename__ = 'tb_mq'

    id_mq = db.Column(db.Integer, db.Sequence('tb_mq_id_mq_seq'), primary_key=True)
    hostname = db.Column(db.String(100), nullable=False)
    port = db.Column(db.Integer, nullable=False)
    channel = db.Column(db.String(100), nullable=False)
    userid = db.Column(db.String(100), nullable=False)
    passwd = db.Column(db.String(100))
    qmgr = db.Column(db.String(100))
    qname = db.Column(db.String(100))
    action = db.Column(db.String(20))
    gettype = db.Column(db.String(30))
    msgtype = db.Column(db.String(20))
    msgid = db.Column(db.String(20))
    ccsid = db.Column(db.String(20))
    ttl = db.Column(db.Integer)
    ssl = db.Column(db.Boolean, default=False)
    tls = db.Column(db.String(20))
    cert = db.Column(db.String(100))

    perfil = db.relationship('Perfil', backref='mq_configs')


class CD(db.Model, BaseProtocol):
    __tablename__ = 'tb_connect_direct'

    id_cd = db.Column(db.Integer, db.Sequence('tb_connect_direct_id_cd_seq'), primary_key=True)
    aut = db.Column(db.String(60))
    dhd = db.Column(db.String(20))
    dst = db.Column(db.String(800))
    tit = db.Column(db.String(240))
    dsn = db.Column(db.String(800))
    dcb = db.Column(db.String(800))
    codbanco = db.Column(db.String(60))
    node = db.Column(db.String(400))
    tsk = db.Column(db.String(240))
    job = db.Column(db.String(240))
    spc = db.Column(db.String(100))
    dmz = db.Column(db.Boolean, default=True)
    disp = db.Column(db.String(60))
    sysopts = db.Column(db.String(800))
    opts = db.Column(db.String(800))

    perfil = db.relationship('Perfil', backref='cd_configs')


class Jasppion(db.Model, BaseProtocol):
    __tablename__ = 'tb_jasppion'

    id_jasppion = db.Column(db.Integer, db.Sequence('tb_jasppion_id_jasppion_seq'), primary_key=True)
    servidor = db.Column(db.String(80))
    porta = db.Column(db.String(10))
    uri = db.Column(db.String(80))
    app = db.Column(db.String(4))
    fsadabas = db.Column(db.String(4))
    logon = db.Column(db.String(10))
    programa = db.Column(db.String(8))
    roscoe = db.Column(db.String(10))
    rcode = db.Column(db.String(4))
    delimitador = db.Column(db.String(60))

    perfil = db.relationship('Perfil', backref='jasppion_configs')


# Base class for functionality configurations
class BaseFunctionality:
    id_perfil = db.Column(db.Integer, db.ForeignKey('tb_perfil.id_perfil'), nullable=False)
    is_deleted = db.Column(db.Boolean, default=False)


class CMD(db.Model, BaseFunctionality):
    __tablename__ = 'tb_cmd'

    id_cmd = db.Column(db.Integer, db.Sequence('tb_cmd_id_cmd_seq'), primary_key=True)
    comando = db.Column(db.String(400))

    perfil = db.relationship('Perfil', backref='cmd_configs')


class Formato(db.Model, BaseFunctionality):
    __tablename__ = 'tb_formato'

    id_formato = db.Column(db.Integer, db.Sequence('tb_formato_id_formato_seq'), primary_key=True)
    de = db.Column(db.String(40))
    para = db.Column(db.String(40))

    perfil = db.relationship('Perfil', backref='formato_configs')


class HeaderTrailer(db.Model, BaseFunctionality):
    __tablename__ = 'tb_header_trailer'

    id_header_trailer = db.Column(db.Integer, db.Sequence('tb_header_trailer_id_header_trailer_seq'), primary_key=True)
    htr0_p1 = db.Column(db.String(20))
    htr0_p2 = db.Column(db.String(20))
    htr1_p1 = db.Column(db.Integer)
    htr1_p2 = db.Column(db.Boolean, default=False)
    htr2 = db.Column(db.Boolean, default=False)
    htr3 = db.Column(db.String(20))
    htr4 = db.Column(db.String(20))
    htr5 = db.Column(db.Boolean, default=False)
    htr6 = db.Column(db.Boolean, default=False)
    htr7 = db.Column(db.Boolean, default=False)
    htr8_p1 = db.Column(db.String(400))
    htr8_p2 = db.Column(db.Boolean, default=False)
    htr9_p1 = db.Column(db.String(20))
    htr9_p2 = db.Column(db.String(20))
    htra = db.Column(db.String(20))

    perfil = db.relationship('Perfil', backref='header_trailer_configs')


class JCL(db.Model, BaseFunctionality):
    __tablename__ = 'tb_jcl'

    id_jcl = db.Column(db.Integer, db.Sequence('tb_jcl_id_jcl_seq'), primary_key=True)
    servidor = db.Column(db.String(80))
    usuario = db.Column(db.String(80))
    jcl = db.Column(db.String(900))
    dmz = db.Column(db.Boolean, default=False)

    perfil = db.relationship('Perfil', backref='jcl_configs')


class Mail(db.Model, BaseFunctionality):
    __tablename__ = 'tb_mail'

    id_mail = db.Column(db.Integer, db.Sequence('tb_mail_id_mail_seq'), primary_key=True)
    msg = db.Column(db.String(2000))
    tit = db.Column(db.String(200))
    dest = db.Column(db.String(1000))
    anexo = db.Column(db.String(50))

    perfil = db.relationship('Perfil', backref='mail_configs')


class PRM(db.Model, BaseFunctionality):
    __tablename__ = 'tb_prm'

    id_prm = db.Column(db.Integer, db.Sequence('tb_prm_id_prm_seq'), primary_key=True)
    # Variables V0-V9
    v0 = db.Column(db.String(20))
    v1 = db.Column(db.String(20))
    v2 = db.Column(db.String(20))
    v3 = db.Column(db.String(20))
    v4 = db.Column(db.String(20))
    v5 = db.Column(db.String(20))
    v6 = db.Column(db.String(20))
    v7 = db.Column(db.String(20))
    v8 = db.Column(db.String(20))
    v9 = db.Column(db.String(20))
    # Numbers N0-N9
    n0 = db.Column(db.String(20))
    n1 = db.Column(db.String(20))
    n2 = db.Column(db.String(20))
    n3 = db.Column(db.String(20))
    n4 = db.Column(db.String(20))
    n5 = db.Column(db.String(20))
    n6 = db.Column(db.String(20))
    n7 = db.Column(db.String(20))
    n8 = db.Column(db.String(20))
    n9 = db.Column(db.String(20))
    # Boolean flags
    bpid = db.Column(db.Boolean, default=False)
    dd = db.Column(db.Boolean, default=False)
    dsu = db.Column(db.Boolean, default=False)
    dsl = db.Column(db.Boolean, default=False)
    dru = db.Column(db.Boolean, default=False)
    drl = db.Column(db.Boolean, default=False)
    mm = db.Column(db.Boolean, default=False)
    mru = db.Column(db.Boolean, default=False)
    mrl = db.Column(db.Boolean, default=False)
    msu = db.Column(db.Boolean, default=False)
    msl = db.Column(db.Boolean, default=False)
    aal = db.Column(db.Boolean, default=False)
    aau = db.Column(db.Boolean, default=False)

    perfil = db.relationship('Perfil', backref='prm_configs')


class Traducao(db.Model, BaseFunctionality):
    __tablename__ = 'tb_traducao'

    id_traducao = db.Column(db.Integer, db.Sequence('tb_traducao_id_traducao_seq'), primary_key=True)
    de = db.Column(db.String(100))
    para = db.Column(db.String(100))

    perfil = db.relationship('Perfil', backref='traducao_configs')


class SER(db.Model, BaseFunctionality):
    __tablename__ = 'tb_ser'

    id_ser = db.Column(db.Integer, db.Sequence('tb_ser_id_ser_seq'), primary_key=True)
    rel = db.Column(db.Boolean, default=False)
    mailc = db.Column(db.Boolean, default=False)
    def_flag = db.Column('def', db.Boolean, default=False)
    zip = db.Column(db.Boolean, default=False)
    crlf = db.Column(db.Boolean, default=False)
    msgsrg_env = db.Column(db.Boolean, default=False)
    aut = db.Column(db.String(100))
    tit = db.Column(db.String(200))
    arquivo = db.Column(db.String(100))
    dst_end = db.Column(db.String(1000))
    dst_roscoe = db.Column(db.String(200))
    dst_mailgroup = db.Column(db.String(200))
    msg = db.Column(db.String(800))

    perfil = db.relationship('Perfil', backref='ser_configs')


# Add synonym to allow using 'def' as field name
setattr(SER, 'def', synonym('def_flag'))


# Independent tables
class FTPUsers(db.Model):
    __tablename__ = 'tb_ftpusers'

    id_ftpusers = db.Column(db.Integer, db.Sequence('tb_ftpusers_id_ftpusers_seq'), primary_key=True)
    usuario = db.Column(db.String(100), unique=True, nullable=False)
    senha = db.Column(db.String(80))
    mf_unit = db.Column(db.String(20))
    is_deleted = db.Column(db.Boolean, default=False)


class MailGroup(db.Model):
    __tablename__ = 'tb_mailgroup'

    id_mailgroup = db.Column(db.Integer, db.Sequence('tb_mailgroup_id_mailgroup_seq'), primary_key=True)
    grupo = db.Column(db.String(60))
    dst = db.Column(db.String(1000))
    is_deleted = db.Column(db.Boolean, default=False)


class Roscoe(db.Model):
    __tablename__ = 'tb_roscoe'

    id_roscoe = db.Column(db.Integer, db.Sequence('tb_roscoe_id_roscoe_seq'), primary_key=True)
    chave = db.Column(db.String(10))
    dst = db.Column(db.String(1000))
    is_deleted = db.Column(db.Boolean, default=False)


class VWPendencias(db.Model):
    __tablename__ = 'vw_pendencias'

    ordem = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.String(50))
    bpname = db.Column(db.String(100))
    parent = db.Column(db.String(100))
    bpid = db.Column(db.String(50))
    destino = db.Column(db.String(200))
    arquivo = db.Column(db.String(200))
    basic_status = db.Column(db.String(50))
    status = db.Column(db.String(50))


class AuditLog(db.Model):
    __tablename__ = 'audit_log'

    id = db.Column(db.Integer, db.Sequence('audit_log_id_seq'), primary_key=True)
    usuario = db.Column(db.String(80))
    operacao = db.Column(db.String(20))
    tabela = db.Column(db.String(50))
    id_registro = db.Column(db.Integer)
    detalhes = db.Column(db.String(500))
    ip_origem = db.Column(db.String(45))
    data_hora = db.Column(db.DateTime, default=datetime.utcnow)


class FAQ(db.Model):
    __tablename__ = 'faq'

    id = db.Column(db.Integer, db.Sequence('faq_id_seq'), primary_key=True)
    categoria = db.Column(db.String(100))
    pergunta = db.Column(db.String(500))
    resposta = db.Column(db.Text)
    imagem_filename = db.Column(db.String(255))
    criado_por = db.Column(db.String(80))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_deleted = db.Column(db.Boolean, default=False)
    deleted_data = db.Column(db.Text)


class SystemConfig(db.Model):
    __tablename__ = 'system_config'

    id = db.Column(db.Integer, db.Sequence('system_config_id_seq'), primary_key=True)
    chave = db.Column(db.String(100), unique=True)
    valor = db.Column(db.Text)
    descricao = db.Column(db.String(500))
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)