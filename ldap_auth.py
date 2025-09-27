"""
LDAP Authentication Module
Provides integration with LDAP servers for user authentication
"""
import ldap
import json
import logging
from datetime import datetime
from utils import get_config_value
from models import User
from app import db

logger = logging.getLogger(__name__)

class LDAPAuthenticator:
    def __init__(self):
        self.server_uri = get_config_value('ldap_server_uri', '')
        self.base_dn = get_config_value('ldap_base_dn', '')
        self.user_dn_template = get_config_value('ldap_user_dn_template', 'cn={username},{base_dn}')
        self.bind_dn = get_config_value('ldap_bind_dn', '')
        self.bind_password = get_config_value('ldap_bind_password', '')
        self.user_search_filter = get_config_value('ldap_user_search_filter', '(cn={username})')
        self.group_search_base = get_config_value('ldap_group_search_base', '')
        self.group_search_filter = get_config_value('ldap_group_search_filter', '(member={user_dn})')
        self.admin_groups = get_config_value('ldap_admin_groups', '').split(',') if get_config_value('ldap_admin_groups', '') else []
        self.enabled = get_config_value('ldap_enabled', 'false').lower() == 'true'
        
    def is_enabled(self):
        """Verifica se a autenticação LDAP está habilitada"""
        return self.enabled and self.server_uri and self.base_dn
    
    def authenticate_user(self, username, password):
        """
        Autentica um usuário no servidor LDAP
        Returns: (success, user_info, error_message)
        """
        if not self.is_enabled():
            return False, None, "LDAP não está configurado ou habilitado"
        
        if not username or not password:
            return False, None, "Usuário e senha são obrigatórios"
        
        try:
            # Conecta ao servidor LDAP
            conn = ldap.initialize(self.server_uri)
            conn.protocol_version = ldap.VERSION3
            conn.set_option(ldap.OPT_REFERRALS, 0)
            
            # Se há bind_dn configurado, faz bind administrativo primeiro
            if self.bind_dn and self.bind_password:
                conn.simple_bind_s(self.bind_dn, self.bind_password)
                
                # Procura o usuário
                search_base = self.base_dn
                search_filter = self.user_search_filter.format(username=ldap.filter.escape_filter_chars(username))
                
                result = conn.search_s(search_base, ldap.SCOPE_SUBTREE, search_filter, ['cn', 'mail', 'memberOf'])
                
                if not result:
                    conn.unbind_s()
                    return False, None, "Usuário não encontrado no LDAP"
                
                user_dn = result[0][0]
                user_attrs = result[0][1]
                
                # Tenta autenticar com as credenciais do usuário
                try:
                    test_conn = ldap.initialize(self.server_uri)
                    test_conn.simple_bind_s(user_dn, password)
                    test_conn.unbind_s()
                except ldap.INVALID_CREDENTIALS:
                    conn.unbind_s()
                    return False, None, "Credenciais inválidas"
                
            else:
                # Autenticação direta
                user_dn = self.user_dn_template.format(username=username, base_dn=self.base_dn)
                conn.simple_bind_s(user_dn, password)
                
                # Busca informações do usuário
                result = conn.search_s(user_dn, ldap.SCOPE_BASE, '(objectClass=*)', ['cn', 'mail', 'memberOf'])
                user_attrs = result[0][1] if result else {}
            
            # Extrai informações do usuário
            user_info = self._extract_user_info(user_dn, user_attrs, username)
            
            # Busca grupos do usuário se configurado
            if self.group_search_base:
                user_info['groups'] = self._get_user_groups(conn, user_dn)
            
            conn.unbind_s()
            return True, user_info, None
            
        except ldap.INVALID_CREDENTIALS:
            return False, None, "Usuário ou senha inválidos"
        except ldap.SERVER_DOWN:
            logger.error(f"Servidor LDAP indisponível: {self.server_uri}")
            return False, None, "Servidor LDAP indisponível"
        except ldap.LDAPError as e:
            logger.error(f"Erro LDAP: {str(e)}")
            return False, None, f"Erro na autenticação LDAP: {str(e)}"
        except Exception as e:
            logger.error(f"Erro inesperado na autenticação LDAP: {str(e)}")
            return False, None, "Erro interno na autenticação"
    
    def _extract_user_info(self, user_dn, user_attrs, username):
        """Extrai informações do usuário dos atributos LDAP"""
        user_info = {
            'username': username,
            'dn': user_dn,
            'email': '',
            'groups': [],
            'is_admin': False
        }
        
        # Email
        if 'mail' in user_attrs and user_attrs['mail']:
            user_info['email'] = user_attrs['mail'][0].decode('utf-8') if isinstance(user_attrs['mail'][0], bytes) else user_attrs['mail'][0]
        
        # Grupos básicos dos atributos do usuário
        if 'memberOf' in user_attrs:
            groups = []
            for group_dn in user_attrs['memberOf']:
                group_dn_str = group_dn.decode('utf-8') if isinstance(group_dn, bytes) else group_dn
                groups.append(group_dn_str)
                
                # Verifica se é admin baseado nos grupos
                for admin_group in self.admin_groups:
                    if admin_group.strip().lower() in group_dn_str.lower():
                        user_info['is_admin'] = True
            
            user_info['groups'] = groups
        
        return user_info
    
    def _get_user_groups(self, conn, user_dn):
        """Busca grupos do usuário usando pesquisa específica"""
        try:
            search_filter = self.group_search_filter.format(user_dn=ldap.filter.escape_filter_chars(user_dn))
            result = conn.search_s(self.group_search_base, ldap.SCOPE_SUBTREE, search_filter, ['cn'])
            
            groups = []
            for group_entry in result:
                if 'cn' in group_entry[1]:
                    group_name = group_entry[1]['cn'][0].decode('utf-8') if isinstance(group_entry[1]['cn'][0], bytes) else group_entry[1]['cn'][0]
                    groups.append(group_name)
            
            return groups
        except ldap.LDAPError as e:
            logger.error(f"Erro ao buscar grupos do usuário: {str(e)}")
            return []
    
    def sync_user_from_ldap(self, username, user_info):
        """
        Sincroniza ou cria um usuário local baseado nas informações do LDAP
        """
        try:
            # Procura usuário existente
            user = User.query.filter_by(username=username).first()
            
            if user:
                # Atualiza usuário existente
                user.auth_type = 'ldap'
                user.ldap_dn = user_info['dn']
                user.ldap_groups = json.dumps(user_info['groups'])
                user.last_login = datetime.utcnow()
                
                # Atualiza email se disponível
                if user_info['email']:
                    user.email = user_info['email']
                
                # Atualiza tipo de usuário baseado nos grupos LDAP
                if user_info['is_admin']:
                    user.user_type = 'avancado'
                else:
                    user.user_type = 'basico'
                    
            else:
                # Cria novo usuário
                user = User(
                    username=username,
                    email=user_info['email'] or f"{username}@ldap.local",
                    auth_type='ldap',
                    ldap_dn=user_info['dn'],
                    ldap_groups=json.dumps(user_info['groups']),
                    user_type='avancado' if user_info['is_admin'] else 'basico',
                    is_active=True,
                    last_login=datetime.utcnow()
                )
                db.session.add(user)
            
            db.session.commit()
            return user
            
        except Exception as e:
            logger.error(f"Erro ao sincronizar usuário LDAP: {str(e)}")
            db.session.rollback()
            return None
    
    def test_connection(self):
        """
        Testa a conexão com o servidor LDAP
        Returns: (success, message)
        """
        if not self.server_uri:
            return False, "URI do servidor LDAP não configurado"
        
        try:
            conn = ldap.initialize(self.server_uri)
            conn.protocol_version = ldap.VERSION3
            conn.set_option(ldap.OPT_REFERRALS, 0)
            conn.set_option(ldap.OPT_NETWORK_TIMEOUT, 10)
            
            if self.bind_dn and self.bind_password:
                conn.simple_bind_s(self.bind_dn, self.bind_password)
                conn.unbind_s()
                return True, "Conexão LDAP bem-sucedida (com bind administrativo)"
            else:
                # Testa apenas a conexão sem bind
                conn.search_s(self.base_dn, ldap.SCOPE_BASE, '(objectClass=*)', ['dn'])
                conn.unbind_s()
                return True, "Conexão LDAP bem-sucedida (sem bind administrativo)"
                
        except ldap.SERVER_DOWN:
            return False, f"Servidor LDAP indisponível: {self.server_uri}"
        except ldap.INVALID_CREDENTIALS:
            return False, "Credenciais de bind administrativo inválidas"
        except ldap.INVALID_DN_SYNTAX:
            return False, "Sintaxe inválida no Base DN ou Bind DN"
        except ldap.NO_SUCH_OBJECT:
            return False, f"Base DN não encontrado: {self.base_dn}"
        except ldap.LDAPError as e:
            return False, f"Erro LDAP: {str(e)}"
        except Exception as e:
            return False, f"Erro inesperado: {str(e)}"

# Instância global do autenticador LDAP
ldap_authenticator = LDAPAuthenticator()