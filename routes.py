import os
import json
import zipfile
import tempfile
import subprocess
from datetime import datetime
from flask import render_template, request, redirect, url_for, flash, jsonify, abort, send_from_directory, session, send_file, Response
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash
from sqlalchemy import or_, desc, text
from app import app, db, login_manager
from models import *
from forms import *
from utils import save_uploaded_file, log_audit, get_statistics, get_recent_activities, check_profile_dependencies, get_connected_users, get_database_configs, save_database_configs, build_connection_strings, get_server_configs, save_server_configs, get_security_configs, save_security_configs, trim_form_data

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Authentication routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    from ldap_auth import ldap_authenticator

    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = None

        # Primeiro, tenta encontrar usuário existente
        existing_user = User.query.filter_by(username=username).first()

        # Se é um usuário local existente ou LDAP não está habilitado
        if existing_user and existing_user.is_local_user():
            if existing_user.check_password(password) and existing_user.is_active:
                user = existing_user
        elif ldap_authenticator.is_enabled():
            # Tenta autenticação LDAP
            success, user_info, error_msg = ldap_authenticator.authenticate_user(username, password)

            if success:
                # Sincroniza usuário LDAP
                user = ldap_authenticator.sync_user_from_ldap(username, user_info)
                if user and not user.is_active:
                    user = None
                    flash('Sua conta foi desativada. Entre em contato com o administrador.', 'warning')
            else:
                # Se falhou no LDAP e existe usuário local, tenta local como fallback
                if existing_user and existing_user.is_local_user():
                    if existing_user.check_password(password) and existing_user.is_active:
                        user = existing_user
                else:
                    flash(f'Falha na autenticação: {error_msg}', 'danger')
        else:
            # Apenas usuários locais (LDAP desabilitado)
            if existing_user and existing_user.check_password(password) and existing_user.is_active:
                user = existing_user

        if user:
            login_user(user)
            user.last_login = datetime.utcnow()
            db.session.commit()

            auth_method = 'LDAP' if user.is_ldap_user() else 'LOCAL'
            log_audit('LOGIN', 'usuarios', user.id, f'Login bem-sucedido ({auth_method}): {user.username}')

            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            if not form.errors:  # Só mostra erro se não houve erros específicos do LDAP
                flash('Usuário ou senha inválidos', 'danger')

    # Verifica se LDAP está habilitado para mostrar no template
    ldap_enabled = ldap_authenticator.is_enabled()

    return render_template('auth/login.html', form=form, ldap_enabled=ldap_enabled)

# Debug route for configuration access
@app.route('/configuracoes/debug')
@login_required
def config_debug():
    debug_info = {
        'user_authenticated': current_user.is_authenticated,
        'username': current_user.username if current_user.is_authenticated else 'N/A',
        'user_type': current_user.user_type if current_user.is_authenticated else 'N/A',
        'is_advanced': current_user.is_advanced() if current_user.is_authenticated else False,
        'is_active': current_user.is_active if current_user.is_authenticated else False
    }
    return jsonify(debug_info)

@app.route('/logout')
@login_required
def logout():
    log_audit('LOGOUT', 'usuarios', current_user.id, f'Logout: {current_user.username}')
    logout_user()
    return redirect(url_for('login'))

# Dashboard
@app.route('/')
@login_required
def dashboard():
    stats = get_statistics()
    recent_activities = get_recent_activities(20)
    connected_users = get_connected_users()
    return render_template('dashboard/index.html', stats=stats, activities=recent_activities, connected_users=connected_users)

@app.route('/api/connected-users')
@login_required
def get_connected_users_api():
    """API endpoint para obter usuários conectados com refresh manual"""
    users = get_connected_users()
    users_data = []
    for user in users[:5]:  # Últimos 5 usuários
        users_data.append({
            'username': user.username,
            'user_type': user.user_type,
            'last_login': user.last_login.strftime('%H:%M') if user.last_login else '-'
        })
    return jsonify({'users': users_data})

# Profile routes
@app.route('/perfis')
@login_required
def list_profiles():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    search = request.args.get('search', '', type=str)

    query = Perfil.query.filter_by(is_deleted=False)

    if search:
        search_pattern = f'%{search}%'
        query = query.filter(or_(
            Perfil.perfil.ilike(search_pattern),
            Perfil.comentario.ilike(search_pattern)
        ))

    profiles = query.order_by(Perfil.perfil).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return render_template('profiles/list.html', profiles=profiles, search=search)

@app.route('/perfis/<int:id>')
@login_required
def view_profile(id):
    profile = Perfil.query.get_or_404(id)
    if profile.is_deleted:
        abort(404)

    # Armazenar o ID do perfil visualizado na sessão para pré-seleção
    session['current_viewing_profile_id'] = id

    # Get related configurations
    related_configs = {}
    if profile.ftp:
        related_configs['ftp'] = FTP.query.filter_by(id_perfil=id, is_deleted=False).all()
    if profile.scp:
        related_configs['scp'] = SCP.query.filter_by(id_perfil=id, is_deleted=False).all()
    if profile.cd:
        related_configs['cd'] = CD.query.filter_by(id_perfil=id, is_deleted=False).all()
    if profile.http:
        related_configs['http'] = HTTP.query.filter_by(id_perfil=id, is_deleted=False).all()
    if profile.jasppion:
        related_configs['jasppion'] = Jasppion.query.filter_by(id_perfil=id, is_deleted=False).all()
    if profile.s3:
        related_configs['s3'] = S3.query.filter_by(id_perfil=id, is_deleted=False).all()
    if profile.mq:
        related_configs['mq'] = MQ.query.filter_by(id_perfil=id, is_deleted=False).all()
    if profile.cmd:
        related_configs['cmd'] = CMD.query.filter_by(id_perfil=id, is_deleted=False).all()
    if profile.formato:
        related_configs['formato'] = Formato.query.filter_by(id_perfil=id, is_deleted=False).all()
    if profile.header_trailer:
        related_configs['header_trailer'] = HeaderTrailer.query.filter_by(id_perfil=id, is_deleted=False).all()
    if profile.jcl:
        related_configs['jcl'] = JCL.query.filter_by(id_perfil=id, is_deleted=False).all()
    if profile.mail:
        related_configs['mail'] = Mail.query.filter_by(id_perfil=id, is_deleted=False).all()
    if profile.prm:
        related_configs['prm'] = PRM.query.filter_by(id_perfil=id, is_deleted=False).all()
    if profile.traducao:
        related_configs['traducao'] = Traducao.query.filter_by(id_perfil=id, is_deleted=False).all()
    if profile.ser:
        related_configs['ser'] = SER.query.filter_by(id_perfil=id, is_deleted=False).all()

    # Get quick actions for enabled functionalities without configurations
    quick_actions = get_quick_actions_for_profile(profile)

    return render_template('profiles/view.html', profile=profile, related_configs=related_configs, quick_actions=quick_actions)

@app.route('/perfis/<int:id>/view')
@login_required
def view_profile_config(id):
    profile = Perfil.query.get_or_404(id)
    if profile.is_deleted:
        abort(404)

    # Build protocols list
    protocols = []
    if profile.ftp: protocols.append('FTP')
    if profile.scp: protocols.append('SCP')
    if profile.cd: protocols.append('Connect:Direct')
    if profile.http: protocols.append('HTTP')
    if profile.jasppion: protocols.append('JASPPION')
    if profile.s3: protocols.append('S3')

    # Build functionalities list
    functionalities = []
    if profile.cmd: functionalities.append('CMD')
    if profile.formato: functionalities.append('Formato')
    if profile.header_trailer: functionalities.append('Header/Trailer')
    if profile.jcl: functionalities.append('JCL')
    if profile.mail: functionalities.append('Mail')
    if profile.prm: functionalities.append('PRM')
    if profile.traducao: functionalities.append('Tradução')
    if profile.ser: functionalities.append('SER')

    profile_data = {
        'id': profile.id_perfil,
        'nome': profile.perfil,
        'cad': profile.cad or '',
        'ass': profile.ass or '',
        'comentario': profile.comentario or '',
        'protocolos': protocols,
        'funcionalidades': functionalities,
        'possui_diagrama': bool(profile.diagram_filename),
        'diagrama_url': url_for('uploaded_file', filename=profile.diagram_filename) if profile.diagram_filename else '',
        'criado_em': profile.created_at.strftime('%d/%m/%Y %H:%M') if profile.created_at else '',
        'atualizado_em': profile.updated_at.strftime('%d/%m/%Y %H:%M') if profile.updated_at else ''
    }
    return jsonify(profile_data)

@app.route('/perfis/novo', methods=['GET', 'POST'])
@login_required
def create_profile():
    if not current_user.is_advanced():
        flash('Acesso negado. Usuários básicos não podem criar perfis.', 'danger')
        return redirect(url_for('list_profiles'))

    form = PerfilForm()
    if form.validate_on_submit():
        # Apply trim to remove leading/trailing whitespace
        form = trim_form_data(form)
        # Check if profile name already exists (including deleted ones for uniqueness)
        existing = Perfil.query.filter_by(perfil=form.perfil.data).first()
        if existing and not existing.is_deleted:
            flash('Já existe um perfil com este nome.', 'danger')
            return render_template('profiles/form.html', form=form, title='Novo Perfil')
        elif existing and existing.is_deleted:
            # If exists but is deleted, we can reuse the name by truly deleting the old record and its dependencies
            # First, delete all related configurations
            FTP.query.filter_by(id_perfil=existing.id_perfil).delete()
            SCP.query.filter_by(id_perfil=existing.id_perfil).delete()
            HTTP.query.filter_by(id_perfil=existing.id_perfil).delete()
            S3.query.filter_by(id_perfil=existing.id_perfil).delete()
            CD.query.filter_by(id_perfil=existing.id_perfil).delete()
            Jasppion.query.filter_by(id_perfil=existing.id_perfil).delete()
            MQ.query.filter_by(id_perfil=existing.id_perfil).delete()
            CMD.query.filter_by(id_perfil=existing.id_perfil).delete()
            JCL.query.filter_by(id_perfil=existing.id_perfil).delete()
            SER.query.filter_by(id_perfil=existing.id_perfil).delete()
            PRM.query.filter_by(id_perfil=existing.id_perfil).delete()
            Formato.query.filter_by(id_perfil=existing.id_perfil).delete()
            Traducao.query.filter_by(id_perfil=existing.id_perfil).delete()
            HeaderTrailer.query.filter_by(id_perfil=existing.id_perfil).delete()
            Mail.query.filter_by(id_perfil=existing.id_perfil).delete()
            # Then delete the profile itself
            db.session.delete(existing)
            db.session.flush()  # Ensure deletion happens before insert

        profile = Perfil()
        # Manually update boolean fields for creation too
        profile.header_trailer = form.header_trailer.data if form.header_trailer.data is not None else False
        profile.prm = form.prm.data if form.prm.data is not None else False
        profile.formato = form.formato.data if form.formato.data is not None else False
        profile.traducao = form.traducao.data if form.traducao.data is not None else False
        profile.scp = form.scp.data if form.scp.data is not None else False
        profile.ftp = form.ftp.data if form.ftp.data is not None else False
        profile.cd = form.cd.data if form.cd.data is not None else False
        profile.cmd = form.cmd.data if form.cmd.data is not None else False
        profile.jcl = form.jcl.data if form.jcl.data is not None else False
        profile.ser = form.ser.data if form.ser.data is not None else False
        profile.mail = form.mail.data if form.mail.data is not None else False
        profile.http = form.http.data if form.http.data is not None else False
        profile.jasppion = form.jasppion.data if form.jasppion.data is not None else False
        profile.s3 = form.s3.data if form.s3.data is not None else False
        profile.mq = form.mq.data if form.mq.data is not None else False

        form.populate_obj(profile)

        # Restore boolean fields (in case populate_obj overwrote them)
        profile.header_trailer = form.header_trailer.data if form.header_trailer.data is not None else False
        profile.prm = form.prm.data if form.prm.data is not None else False
        profile.formato = form.formato.data if form.formato.data is not None else False
        profile.traducao = form.traducao.data if form.traducao.data is not None else False
        profile.scp = form.scp.data if form.scp.data is not None else False
        profile.ftp = form.ftp.data if form.ftp.data is not None else False
        profile.cd = form.cd.data if form.cd.data is not None else False
        profile.cmd = form.cmd.data if form.cmd.data is not None else False
        profile.jcl = form.jcl.data if form.jcl.data is not None else False
        profile.ser = form.ser.data if form.ser.data is not None else False
        profile.mail = form.mail.data if form.mail.data is not None else False
        profile.http = form.http.data if form.http.data is not None else False
        profile.jasppion = form.jasppion.data if form.jasppion.data is not None else False
        profile.s3 = form.s3.data if form.s3.data is not None else False
        profile.mq = form.mq.data if form.mq.data is not None else False

        # Handle file upload
        if form.diagram.data:
            filename = save_uploaded_file(form.diagram.data)
            if filename:
                profile.diagram_filename = filename

        db.session.add(profile)
        db.session.commit()

        log_audit('CREATE', 'tb_perfil', profile.id_perfil, f'Perfil criado: {profile.perfil}')
        flash('Perfil criado com sucesso!', 'success')

        # Armazenar o ID do perfil recém-criado na sessão para pré-seleção
        session['last_created_profile_id'] = profile.id_perfil

        return redirect(url_for('view_profile', id=profile.id_perfil))

    # Para novo perfil, não há ações rápidas (perfil ainda não foi salvo)
    return render_template('profiles/form.html', form=form, title='Novo Perfil', quick_actions=[])

@app.route('/perfis/<int:id>/editar', methods=['GET', 'POST'])
@login_required
def edit_profile(id):
    if not current_user.is_advanced():
        flash('Acesso negado. Usuários básicos não podem editar perfis.', 'danger')
        return redirect(url_for('view_profile', id=id))

    profile = Perfil.query.get_or_404(id)
    if profile.is_deleted:
        abort(404)

    form = PerfilForm(obj=profile)
    if form.validate_on_submit():
        # Apply trim to remove leading/trailing whitespace
        form = trim_form_data(form)
        # Check if profile name already exists (excluding current profile)
        existing = Perfil.query.filter(
            Perfil.perfil == form.perfil.data,
            Perfil.id_perfil != id
        ).first()
        if existing and not existing.is_deleted:
            flash('Já existe um perfil com este nome.', 'danger')
            quick_actions = get_quick_actions_for_profile(profile)
            return render_template('profiles/form.html', form=form, title='Editar Perfil', profile=profile, quick_actions=quick_actions)
        elif existing and existing.is_deleted:
            # If exists but is deleted, we can reuse the name by truly deleting the old record and its dependencies
            # First, delete all related configurations
            FTP.query.filter_by(id_perfil=existing.id_perfil).delete()
            SCP.query.filter_by(id_perfil=existing.id_perfil).delete()
            HTTP.query.filter_by(id_perfil=existing.id_perfil).delete()
            S3.query.filter_by(id_perfil=existing.id_perfil).delete()
            CD.query.filter_by(id_perfil=existing.id_perfil).delete()
            Jasppion.query.filter_by(id_perfil=existing.id_perfil).delete()
            MQ.query.filter_by(id_perfil=existing.id_perfil).delete()
            CMD.query.filter_by(id_perfil=existing.id_perfil).delete()
            JCL.query.filter_by(id_perfil=existing.id_perfil).delete()
            SER.query.filter_by(id_perfil=existing.id_perfil).delete()
            PRM.query.filter_by(id_perfil=existing.id_perfil).delete()
            Formato.query.filter_by(id_perfil=existing.id_perfil).delete()
            Traducao.query.filter_by(id_perfil=existing.id_perfil).delete()
            HeaderTrailer.query.filter_by(id_perfil=existing.id_perfil).delete()
            Mail.query.filter_by(id_perfil=existing.id_perfil).delete()
            # Then delete the profile itself
            db.session.delete(existing)
            db.session.flush()  # Ensure deletion happens before update

        old_name = profile.perfil

        # Manually update boolean fields first
        profile.header_trailer = form.header_trailer.data if form.header_trailer.data is not None else False
        profile.prm = form.prm.data if form.prm.data is not None else False
        profile.formato = form.formato.data if form.formato.data is not None else False
        profile.traducao = form.traducao.data if form.traducao.data is not None else False
        profile.scp = form.scp.data if form.scp.data is not None else False
        profile.ftp = form.ftp.data if form.ftp.data is not None else False
        profile.cd = form.cd.data if form.cd.data is not None else False
        profile.cmd = form.cmd.data if form.cmd.data is not None else False
        profile.jcl = form.jcl.data if form.jcl.data is not None else False
        profile.ser = form.ser.data if form.ser.data is not None else False
        profile.mail = form.mail.data if form.mail.data is not None else False
        profile.http = form.http.data if form.http.data is not None else False
        profile.jasppion = form.jasppion.data if form.jasppion.data is not None else False
        profile.s3 = form.s3.data if form.s3.data is not None else False
        profile.mq = form.mq.data if form.mq.data is not None else False

        # Then populate other fields
        form.populate_obj(profile)

        # Restore boolean fields (in case populate_obj overwrote them)
        profile.header_trailer = form.header_trailer.data if form.header_trailer.data is not None else False
        profile.prm = form.prm.data if form.prm.data is not None else False
        profile.formato = form.formato.data if form.formato.data is not None else False
        profile.traducao = form.traducao.data if form.traducao.data is not None else False
        profile.scp = form.scp.data if form.scp.data is not None else False
        profile.ftp = form.ftp.data if form.ftp.data is not None else False
        profile.cd = form.cd.data if form.cd.data is not None else False
        profile.cmd = form.cmd.data if form.cmd.data is not None else False
        profile.jcl = form.jcl.data if form.jcl.data is not None else False
        profile.ser = form.ser.data if form.ser.data is not None else False
        profile.mail = form.mail.data if form.mail.data is not None else False
        profile.http = form.http.data if form.http.data is not None else False
        profile.jasppion = form.jasppion.data if form.jasppion.data is not None else False
        profile.s3 = form.s3.data if form.s3.data is not None else False
        profile.mq = form.mq.data if form.mq.data is not None else False

        # Handle file upload
        if form.diagram.data:
            filename = save_uploaded_file(form.diagram.data)
            if filename:
                # Remove old file if exists
                if profile.diagram_filename:
                    old_file_path = os.path.join(app.config['UPLOAD_FOLDER'], profile.diagram_filename)
                    if os.path.exists(old_file_path):
                        os.remove(old_file_path)
                profile.diagram_filename = filename

        profile.updated_at = datetime.utcnow()
        db.session.commit()

        log_audit('UPDATE', 'tb_perfil', profile.id_perfil, f'Perfil atualizado: {old_name} -> {profile.perfil}')
        flash('Perfil atualizado com sucesso!', 'success')

        # Check if coming from advanced search
        if request.referrer and 'busca-avancada' in request.referrer:
            return redirect(url_for('advanced_search'))
        return redirect(url_for('view_profile', id=id))

    # Calcula ações rápidas para funcionalidades habilitadas sem registros
    quick_actions = get_quick_actions_for_profile(profile)
    return render_template('profiles/form.html', form=form, title='Editar Perfil', profile=profile, quick_actions=quick_actions)

@app.route('/perfis/<int:id>/duplicar', methods=['POST'])
@login_required
def duplicate_profile(id):
    if not current_user.is_advanced():
        flash('Acesso negado. Usuários básicos não podem duplicar perfis.', 'danger')
        return redirect(url_for('view_profile', id=id))

    original = Perfil.query.get_or_404(id)
    if original.is_deleted:
        abort(404)

    # Create new profile name
    new_name = f"{original.perfil}_COPY"
    counter = 1
    while Perfil.query.filter_by(perfil=new_name, is_deleted=False).first():
        new_name = f"{original.perfil}_COPY_{counter}"
        counter += 1

    # Duplicate profile
    new_profile = Perfil(
        perfil=new_name,
        cad=original.cad,
        ass=original.ass,
        comentario=original.comentario,
        header_trailer=original.header_trailer,
        prm=original.prm,
        formato=original.formato,
        traducao=original.traducao,
        scp=original.scp,
        ftp=original.ftp,
        cd=original.cd,
        cmd=original.cmd,
        jcl=original.jcl,
        ser=original.ser,
        mail=original.mail,
        http=original.http,
        jasppion=original.jasppion,
        s3=original.s3
    )

    db.session.add(new_profile)
    db.session.flush()  # Get the new profile ID

    # Duplicate related configurations
    if original.ftp:
        for ftp in FTP.query.filter_by(id_perfil=id, is_deleted=False).all():
            new_ftp = FTP(id_perfil=new_profile.id_perfil)
            for column in FTP.__table__.columns:
                if column.name not in ['id_ftp', 'id_perfil']:
                    setattr(new_ftp, column.name, getattr(ftp, column.name))
            db.session.add(new_ftp)

    # Add similar duplication for other protocol configurations...
    if original.scp:
        for scp in SCP.query.filter_by(id_perfil=id, is_deleted=False).all():
            new_scp = SCP(id_perfil=new_profile.id_perfil)
            for column in SCP.__table__.columns:
                if column.name not in ['id_scp', 'id_perfil']:
                    setattr(new_scp, column.name, getattr(scp, column.name))
            db.session.add(new_scp)

    if original.http:
        for http in HTTP.query.filter_by(id_perfil=id, is_deleted=False).all():
            new_http = HTTP(id_perfil=new_profile.id_perfil)
            for column in HTTP.__table__.columns:
                if column.name not in ['id_http', 'id_perfil']:
                    setattr(new_http, column.name, getattr(http, column.name))
            db.session.add(new_http)

    if original.s3:
        for s3 in S3.query.filter_by(id_perfil=id, is_deleted=False).all():
            new_s3 = S3(id_perfil=new_profile.id_perfil)
            for column in S3.__table__.columns:
                if column.name not in ['id_s3', 'id_perfil']:
                    setattr(new_s3, column.name, getattr(s3, column.name))
            db.session.add(new_s3)

    if original.cd:
        for cd in CD.query.filter_by(id_perfil=id, is_deleted=False).all():
            new_cd = CD(id_perfil=new_profile.id_perfil)
            for column in CD.__table__.columns:
                if column.name not in ['id_cd', 'id_perfil']:
                    setattr(new_cd, column.name, getattr(cd, column.name))
            db.session.add(new_cd)

    if original.jasppion:
        for jasppion in Jasppion.query.filter_by(id_perfil=id, is_deleted=False).all():
            new_jasppion = Jasppion(id_perfil=new_profile.id_perfil)
            for column in Jasppion.__table__.columns:
                if column.name not in ['id_jasppion', 'id_perfil']:
                    setattr(new_jasppion, column.name, getattr(jasppion, column.name))
            db.session.add(new_jasppion)

    if original.mq:
        for mq in MQ.query.filter_by(id_perfil=id, is_deleted=False).all():
            new_mq = MQ(id_perfil=new_profile.id_perfil)
            for column in MQ.__table__.columns:
                if column.name not in ['id_mq', 'id_perfil']:
                    setattr(new_mq, column.name, getattr(mq, column.name))
            db.session.add(new_mq)

    if original.cmd:
        for cmd in CMD.query.filter_by(id_perfil=id, is_deleted=False).all():
            new_cmd = CMD(id_perfil=new_profile.id_perfil)
            for column in CMD.__table__.columns:
                if column.name not in ['id_cmd', 'id_perfil']:
                    setattr(new_cmd, column.name, getattr(cmd, column.name))
            db.session.add(new_cmd)

    if original.formato:
        for formato in Formato.query.filter_by(id_perfil=id, is_deleted=False).all():
            new_formato = Formato(id_perfil=new_profile.id_perfil)
            for column in Formato.__table__.columns:
                if column.name not in ['id_formato', 'id_perfil']:
                    setattr(new_formato, column.name, getattr(formato, column.name))
            db.session.add(new_formato)

    if original.header_trailer:
        for ht in HeaderTrailer.query.filter_by(id_perfil=id, is_deleted=False).all():
            new_ht = HeaderTrailer(id_perfil=new_profile.id_perfil)
            for column in HeaderTrailer.__table__.columns:
                if column.name not in ['id_header_trailer', 'id_perfil']:
                    setattr(new_ht, column.name, getattr(ht, column.name))
            db.session.add(new_ht)

    if original.jcl:
        for jcl in JCL.query.filter_by(id_perfil=id, is_deleted=False).all():
            new_jcl = JCL(id_perfil=new_profile.id_perfil)
            for column in JCL.__table__.columns:
                if column.name not in ['id_jcl', 'id_perfil']:
                    setattr(new_jcl, column.name, getattr(jcl, column.name))
            db.session.add(new_jcl)

    if original.mail:
        for mail in Mail.query.filter_by(id_perfil=id, is_deleted=False).all():
            new_mail = Mail(id_perfil=new_profile.id_perfil)
            for column in Mail.__table__.columns:
                if column.name not in ['id_mail', 'id_perfil']:
                    setattr(new_mail, column.name, getattr(mail, column.name))
            db.session.add(new_mail)

    if original.prm:
        for prm in PRM.query.filter_by(id_perfil=id, is_deleted=False).all():
            new_prm = PRM(id_perfil=new_profile.id_perfil)
            for column in PRM.__table__.columns:
                if column.name not in ['id_prm', 'id_perfil']:
                    setattr(new_prm, column.name, getattr(prm, column.name))
            db.session.add(new_prm)

    if original.traducao:
        for traducao in Traducao.query.filter_by(id_perfil=id, is_deleted=False).all():
            new_traducao = Traducao(id_perfil=new_profile.id_perfil)
            for column in Traducao.__table__.columns:
                if column.name not in ['id_traducao', 'id_perfil']:
                    setattr(new_traducao, column.name, getattr(traducao, column.name))
            db.session.add(new_traducao)

    if original.ser:
        for ser in SER.query.filter_by(id_perfil=id, is_deleted=False).all():
            new_ser = SER(id_perfil=new_profile.id_perfil)
            for column in SER.__table__.columns:
                if column.name not in ['id_ser', 'id_perfil']:
                    setattr(new_ser, column.name, getattr(ser, column.name))
            db.session.add(new_ser)

    db.session.commit()

    log_audit('CREATE', 'tb_perfil', new_profile.id_perfil, f'Perfil duplicado de: {original.perfil}')
    flash(f'Perfil duplicado com sucesso como "{new_name}"!', 'success')
    return redirect(url_for('view_profile', id=new_profile.id_perfil))

@app.route('/perfis/<int:id>/deletar', methods=['POST'])
@login_required
def delete_profile(id):
    if not current_user.is_advanced():
        flash('Acesso negado. Usuários básicos não podem deletar perfis.', 'danger')
        return redirect(url_for('view_profile', id=id))

    profile = Perfil.query.get_or_404(id)
    if profile.is_deleted:
        abort(404)

    # Check dependencies
    dependencies = check_profile_dependencies(id)
    if dependencies:
        flash(f'Não é possível deletar o perfil. Existem configurações associadas: {", ".join(dependencies)}', 'danger')
        return redirect(url_for('view_profile', id=id))

    # Salva dados completos para restauração
    import json
    profile_data = {
        'perfil': profile.perfil,
        'cad': profile.cad or '',
        'ass': profile.ass or '',
        'comentario': profile.comentario or '',
        'ftp': profile.ftp,
        'scp': profile.scp,
        'http': profile.http,
        's3': profile.s3,
        'cd': profile.cd,
        'jasppion': profile.jasppion,
        'cmd': profile.cmd,
        'jcl': profile.jcl,
        'ser': profile.ser,
        'prm': profile.prm,
        'formato': profile.formato,
        'traducao': profile.traducao,
        'header_trailer': profile.header_trailer,
        'mail': profile.mail,
        'diagram_filename': profile.diagram_filename or ''
    }

    profile.is_deleted = True
    db.session.commit()

    log_audit('DELETE', 'tb_perfil', id, json.dumps(profile_data, ensure_ascii=False))
    flash('Perfil deletado com sucesso!', 'success')
    return redirect(url_for('list_profiles'))

# FTP routes
@app.route('/protocolos/ftp')
@login_required
def list_ftp():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    search = request.args.get('search', '', type=str)

    query = db.session.query(FTP, Perfil).join(Perfil).filter(FTP.is_deleted == False)

    if search:
        search_pattern = f'%{search}%'
        query = query.filter(or_(
            Perfil.perfil.ilike(search_pattern),
            FTP.servidor.ilike(search_pattern),
            FTP.usuario.ilike(search_pattern)
        ))

    configs = query.order_by(Perfil.perfil).paginate(
        page=page, per_page=per_page, error_out=False
    )

    # Buscar perfis com FTP habilitado para o dropdown
    perfis_ftp = Perfil.query.filter_by(ftp=True, is_deleted=False).all()

    return render_template('protocols/ftp.html', configs=configs, search=search, perfis_ftp=perfis_ftp)

@app.route('/protocolos/ftp/novo', methods=['GET', 'POST'])
@login_required
def create_ftp():
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_ftp'))

    form = FTPForm()
    # Populate profile choices
    perfis_ftp = Perfil.query.filter_by(ftp=True, is_deleted=False).all()
    form.perfil_id.choices = [(p.id_perfil, p.perfil) for p in perfis_ftp]

    # Pré-selecionar perfil (recém-criado ou visualizado)
    preselect_profile_id = session.get('last_created_profile_id') or session.get('current_viewing_profile_id')
    if preselect_profile_id and any(p.id_perfil == preselect_profile_id for p in perfis_ftp):
        form.perfil_id.data = preselect_profile_id
        # Remover apenas o perfil recém-criado da sessão após usar
        session.pop('last_created_profile_id', None)

    if form.validate_on_submit():
        # Apply trim to remove leading/trailing whitespace
        form = trim_form_data(form)
        perfil = Perfil.query.get_or_404(form.perfil_id.data)
        if not perfil.ftp or perfil.is_deleted:
            flash('Perfil não permite configuração FTP.', 'danger')
            return redirect(url_for('list_ftp'))

        ftp_config = FTP(id_perfil=form.perfil_id.data)
        form.populate_obj(ftp_config)

        db.session.add(ftp_config)
        db.session.commit()

        log_audit('CREATE', 'tb_ftp', ftp_config.id_ftp, f'Configuração FTP criada para perfil: {perfil.perfil}')
        flash('Configuração FTP criada com sucesso!', 'success')
        return redirect(url_for('list_ftp'))

    return render_template('protocols/ftp_form.html', form=form, title='Nova Configuração FTP')

@app.route('/protocolos/ftp/<int:id>/view')
@login_required
def view_ftp_config(id):
    ftp_config = FTP.query.get_or_404(id)
    if ftp_config.is_deleted:
        abort(404)

    config_data = {
        'id': ftp_config.id_ftp,
        'perfil': ftp_config.perfil.perfil,
        'servidor': ftp_config.servidor or '',
        'porta': ftp_config.porta or 21,
        'usuario': ftp_config.usuario or '',
        'dir_local': ftp_config.dir_local or '',
        'dir_remoto': ftp_config.dir_remoto or '',
        'arquivo_local': ftp_config.arquivo_local or '',
        'arquivo_remoto': ftp_config.arquivo_remoto or '',
        'comando': ftp_config.comando or '',
        'q_site': ftp_config.q_site or '',
        'cert': ftp_config.cert or '',
        'zip': ftp_config.zip or False,
        'crlf': ftp_config.crlf or False,
        'bin': ftp_config.bin or False,
        'rel': ftp_config.rel or False,
        'def_flag': ftp_config.def_flag or False,
        'cdup': ftp_config.cdup or True,
        'code': ftp_config.code or False,
        'dmz': ftp_config.dmz or False,
        'mail': ftp_config.mail or False,
        'mailass': ftp_config.mailass or '',
        'maildest': ftp_config.maildest or '',
        'mailmsg': ftp_config.mailmsg or '',
        'mailanexo': ftp_config.mailanexo or False
    }
    return jsonify(config_data)

@app.route('/protocolos/ftp/<int:id>/editar', methods=['GET', 'POST'])
@login_required
def edit_ftp(id):
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_ftp'))

    ftp_config = FTP.query.get_or_404(id)
    if ftp_config.is_deleted:
        abort(404)

    form = FTPForm(obj=ftp_config)
    # Populate profile choices
    perfis_ftp = Perfil.query.filter_by(ftp=True, is_deleted=False).all()
    form.perfil_id.choices = [(p.id_perfil, p.perfil) for p in perfis_ftp]
    # Pre-select the current profile
    form.perfil_id.data = ftp_config.id_perfil
    if form.validate_on_submit():
        # Apply trim to remove leading/trailing whitespace
        form = trim_form_data(form)
        # Manually update boolean fields
        ftp_config.zip = form.zip.data if form.zip.data is not None else False
        ftp_config.crlf = form.crlf.data if form.crlf.data is not None else False
        ftp_config.rel = form.rel.data if form.rel.data is not None else False
        ftp_config.bin = form.bin.data if form.bin.data is not None else False
        ftp_config.def_flag = form.def_flag.data if form.def_flag.data is not None else False
        ftp_config.cdup = form.cdup.data if form.cdup.data is not None else True
        ftp_config.dmz = form.dmz.data if form.dmz.data is not None else False
        ftp_config.code = form.code.data if form.code.data is not None else False
        ftp_config.mail = form.mail.data if form.mail.data is not None else False
        ftp_config.mailanexo = form.mailanexo.data if form.mailanexo.data is not None else False

        form.populate_obj(ftp_config)

        # Restore boolean fields
        ftp_config.zip = form.zip.data if form.zip.data is not None else False
        ftp_config.crlf = form.crlf.data if form.crlf.data is not None else False
        ftp_config.rel = form.rel.data if form.rel.data is not None else False
        ftp_config.bin = form.bin.data if form.bin.data is not None else False
        ftp_config.def_flag = form.def_flag.data if form.def_flag.data is not None else False
        ftp_config.cdup = form.cdup.data if form.cdup.data is not None else True
        ftp_config.dmz = form.dmz.data if form.dmz.data is not None else False
        ftp_config.code = form.code.data if form.code.data is not None else False
        ftp_config.mail = form.mail.data if form.mail.data is not None else False
        ftp_config.mailanexo = form.mailanexo.data if form.mailanexo.data is not None else False

        db.session.commit()

        log_audit('UPDATE', 'tb_ftp', id, f'Configuração FTP editada para perfil: {ftp_config.perfil.perfil}')
        flash('Configuração FTP atualizada com sucesso!', 'success')

        # Check if coming from advanced search
        if request.referrer and 'busca-avancada' in request.referrer:
            return redirect(url_for('advanced_search'))
        return redirect(url_for('list_ftp'))

    return render_template('protocols/ftp_form.html', form=form, ftp_config=ftp_config, title='Editar Configuração FTP')

@app.route('/protocolos/ftp/<int:id>/deletar', methods=['POST'])
@login_required
def delete_ftp(id):
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_ftp'))

    ftp_config = FTP.query.get_or_404(id)
    if ftp_config.is_deleted:
        abort(404)

    # Salva dados para possível restauração
    import json
    ftp_data = {
        'perfil_id': ftp_config.id_perfil,
        'servidor': ftp_config.servidor,
        'porta': ftp_config.porta,
        'usuario': ftp_config.usuario,
        'senha': ftp_config.senha,
        'dir_local': ftp_config.dir_local,
        'dir_remoto': ftp_config.dir_remoto,
        'arquivo_local': ftp_config.arquivo_local,
        'arquivo_remoto': ftp_config.arquivo_remoto,
        'comando': ftp_config.comando,
        'zip': ftp_config.zip,
        'crlf': ftp_config.crlf,
        'bin': ftp_config.bin,
        'dmz': ftp_config.dmz
    }

    ftp_config.is_deleted = True
    db.session.commit()

    log_audit('DELETE', 'tb_ftp', id, json.dumps(ftp_data, ensure_ascii=False))
    flash('Configuração FTP deletada com sucesso!', 'success')
    return redirect(url_for('list_ftp'))

# Users management
@app.route('/usuarios')
@login_required
def list_users():
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('dashboard'))

    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    search = request.args.get('search', '', type=str)

    query = User.query

    if search:
        search_pattern = f'%{search}%'
        query = query.filter(or_(
            User.username.ilike(search_pattern),
            User.email.ilike(search_pattern)
        ))

    users = query.order_by(User.username).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return render_template('users/list.html', users=users, search=search)

@app.route('/usuarios/novo', methods=['GET', 'POST'])
@login_required
def create_user():
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_users'))

    form = UserForm()
    if form.validate_on_submit():
        # Apply trim to remove leading/trailing whitespace
        form = trim_form_data(form)
        # Check if username already exists
        existing = User.query.filter_by(username=form.username.data).first()
        if existing:
            flash('Já existe um usuário com este nome.', 'danger')
            return render_template('users/form.html', form=form, title='Novo Usuário')

        user = User()
        form.populate_obj(user)

        if form.password.data:
            user.set_password(form.password.data)

        db.session.add(user)
        db.session.commit()

        log_audit('CREATE', 'usuarios', user.id, f'Usuário criado: {user.username}')
        flash('Usuário criado com sucesso!', 'success')
        return redirect(url_for('list_users'))

    return render_template('users/form.html', form=form, title='Novo Usuário')

@app.route('/usuarios/<int:id>/editar', methods=['GET', 'POST'])
@login_required
def edit_user(id):
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_users'))

    user = User.query.get_or_404(id)
    form = UserForm(obj=user)

    if form.validate_on_submit():
        # Apply trim to remove leading/trailing whitespace
        form = trim_form_data(form)
        # Check if username already exists (excluding current user)
        existing = User.query.filter(User.username == form.username.data, User.id != id).first()
        if existing:
            flash('Já existe um usuário com este nome.', 'danger')
            return render_template('users/form.html', form=form, user=user, title='Editar Usuário')

        # Check if email already exists (excluding current user)
        existing_email = User.query.filter(User.email == form.email.data, User.id != id).first()
        if existing_email:
            flash('Já existe um usuário com este email.', 'danger')
            return render_template('users/form.html', form=form, user=user, title='Editar Usuário')

        form.populate_obj(user)

        # Only update password if provided
        if form.password.data:
            user.set_password(form.password.data)

        db.session.commit()

        log_audit('UPDATE', 'usuarios', user.id, f'Usuário editado: {user.username}')
        flash('Usuário atualizado com sucesso!', 'success')
        return redirect(url_for('list_users'))

    return render_template('users/form.html', form=form, user=user, title='Editar Usuário')

@app.route('/usuarios/<int:id>/visualizar')
@login_required
def view_user(id):
    user = User.query.get_or_404(id)
    return render_template('users/view.html', user=user)

@app.route('/usuarios/<int:id>/deletar', methods=['POST'])
@login_required
def delete_user(id):
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_users'))

    user = User.query.get_or_404(id)

    # Prevent deleting yourself
    if user.id == current_user.id:
        flash('Você não pode deletar sua própria conta.', 'danger')
        return redirect(url_for('list_users'))

    # Salva dados para possível restauração
    import json
    user_data = {
        'username': user.username,
        'email': user.email,
        'password_hash': user.password_hash,
        'user_type': user.user_type,
        'is_active': user.is_active,
        'auth_type': user.auth_type,
        'ldap_dn': user.ldap_dn
    }

    username = user.username
    db.session.delete(user)
    db.session.commit()

    log_audit('DELETE', 'usuarios', id, json.dumps(user_data, ensure_ascii=False))
    flash('Usuário deletado com sucesso!', 'success')
    return redirect(url_for('list_users'))

# Audit history
@app.route('/historico')
@login_required
def audit_history():
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('dashboard'))

    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    search = request.args.get('search', '', type=str)
    operation_filter = request.args.get('operacao', '', type=str)

    query = AuditLog.query

    if search:
        search_pattern = f'%{search}%'
        query = query.filter(or_(
            AuditLog.usuario.ilike(search_pattern),
            AuditLog.detalhes.ilike(search_pattern),
            AuditLog.tabela.ilike(search_pattern)
        ))

    if operation_filter:
        query = query.filter(AuditLog.operacao == operation_filter)

    audit_logs = query.order_by(desc(AuditLog.data_hora)).paginate(
        page=page, per_page=per_page, error_out=False
    )

    # Get operation statistics
    operations = ['CREATE', 'UPDATE', 'DELETE', 'RESTORE', 'LOGIN']
    
    # Calculate statistics for each operation
    stats = {}
    for op in operations:
        stats[op] = AuditLog.query.filter_by(operacao=op).count()
    stats['TOTAL'] = AuditLog.query.count()

    return render_template('history/list.html',
                         audit_logs=audit_logs,
                         search=search,
                         operation_filter=operation_filter,
                         operations=operations,
                         stats=stats)

@app.route('/historico/restaurar/<string:table>/<int:record_id>', methods=['POST'])
@login_required
def restore_record(table, record_id):
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('audit_history'))

    try:
        # Busca o registro de auditoria da exclusão
        audit_log = AuditLog.query.filter_by(
            operacao='DELETE',
            tabela=table,
            id_registro=record_id
        ).order_by(desc(AuditLog.data_hora)).first()

        if not audit_log:
            flash('Registro de exclusão não encontrado.', 'danger')
            return redirect(url_for('audit_history'))

        # Parse dos detalhes para recuperar os dados
        import json
        try:
            deleted_data = json.loads(audit_log.detalhes)
        except (json.JSONDecodeError, TypeError):
            flash('Dados de restauração inválidos.', 'danger')
            return redirect(url_for('audit_history'))

        restored = False

        # Restaura conforme o tipo de tabela
        if table == 'tb_perfil':
            restored = restore_profile(deleted_data, record_id)
        elif table == 'tb_ftp':
            restored = restore_ftp_config(deleted_data, record_id)
        elif table == 'tb_scp':
            restored = restore_scp_config(deleted_data, record_id)
        elif table == 'tb_http':
            restored = restore_http_config(deleted_data, record_id)
        elif table == 'tb_s3':
            restored = restore_s3_config(deleted_data, record_id)
        elif table == 'tb_connect_direct':
            restored = restore_connect_direct_config(deleted_data, record_id)
        elif table == 'tb_jasppion':
            restored = restore_jasppion_config(deleted_data, record_id)
        elif table == 'tb_cmd':
            restored = restore_cmd_config(deleted_data, record_id)
        elif table == 'tb_formato':
            restored = restore_formato_config(deleted_data, record_id)
        elif table == 'tb_jcl':
            restored = restore_jcl_config(deleted_data, record_id)
        elif table == 'tb_prm':
            restored = restore_prm_config(deleted_data, record_id)
        elif table == 'tb_traducao':
            restored = restore_traducao_config(deleted_data, record_id)
        elif table == 'tb_ser':
            restored = restore_ser_config(deleted_data, record_id)
        elif table == 'tb_header_trailer':
            restored = restore_header_trailer_config(deleted_data, record_id)
        elif table == 'tb_mail':
            restored = restore_mail_config(deleted_data, record_id)
        elif table == 'usuarios':
            restored = restore_user(deleted_data, record_id)
        elif table == 'tb_faq':
            restored = restore_faq(deleted_data, record_id)
        elif table == 'tb_ftpusers':
            restored = restore_ftpusers(deleted_data, record_id)
        elif table == 'tb_mailgroup':
            restored = restore_mailgroup(deleted_data, record_id)
        elif table == 'tb_roscoe':
            restored = restore_roscoe(deleted_data, record_id)
        elif table == 'tb_mq':
            restored = restore_mq_config(deleted_data, record_id)
        else:
            flash(f'Tipo de tabela "{table}" não suportado para restauração.', 'warning')
            return redirect(url_for('audit_history'))

        if restored:
            # Log da restauração
            log_audit('RESTORE', table, record_id, f'Registro restaurado: {deleted_data.get("nome", deleted_data.get("perfil", "ID " + str(record_id)))}')
            flash('Registro restaurado com sucesso!', 'success')
        else:
            flash('Erro ao restaurar registro.', 'danger')

    except Exception as e:
        db.session.rollback()
        flash(f'Erro interno ao restaurar registro: {str(e)}', 'danger')

    return redirect(url_for('audit_history'))

def restore_profile(data, record_id):
    """Restaura um perfil excluído"""
    try:
        # Verifica se já existe perfil ativo com mesmo nome (não verifica perfis deletados)
        existing = Perfil.query.filter_by(perfil=data.get('perfil'), is_deleted=False).first()
        if existing:
            flash(f'Já existe um perfil ativo com o nome "{data.get("perfil")}".', 'warning')
            return False

        # Verifica se o perfil deletado existe e pode ser restaurado
        deleted_profile = Perfil.query.get(record_id)
        if deleted_profile and deleted_profile.is_deleted:
            # Restaura marcando como não deletado
            deleted_profile.is_deleted = False
            deleted_profile.perfil = data.get('perfil')
            deleted_profile.descricao = data.get('descricao', '')
            deleted_profile.ativo = data.get('ativo', True)
            deleted_profile.ftp = data.get('ftp', False)
            deleted_profile.scp = data.get('scp', False)
            deleted_profile.http = data.get('http', False)
            deleted_profile.s3 = data.get('s3', False)
            deleted_profile.cd = data.get('cd', False)
            deleted_profile.jasppion = data.get('jasppion', False)
            deleted_profile.cmd = data.get('cmd', False)
            deleted_profile.jcl = data.get('jcl', False)
            deleted_profile.ser = data.get('ser', False)
            deleted_profile.prm = data.get('prm', False)
            deleted_profile.formato = data.get('formato', False)
            deleted_profile.traducao = data.get('traducao', False)
            deleted_profile.header_trailer = data.get('header_trailer', False)
            deleted_profile.mail = data.get('mail', False)
            deleted_profile.diagram_filename = data.get('diagram_filename')

            db.session.commit()
            return True
        else:
            # Se o registro não existe mais, cria um novo
            profile = Perfil(
                perfil=data.get('perfil'),
                descricao=data.get('descricao', ''),
                ativo=data.get('ativo', True),
                ftp=data.get('ftp', False),
                scp=data.get('scp', False),
                http=data.get('http', False),
                s3=data.get('s3', False),
                cd=data.get('cd', False),
                jasppion=data.get('jasppion', False),
                cmd=data.get('cmd', False),
                jcl=data.get('jcl', False),
                ser=data.get('ser', False),
                prm=data.get('prm', False),
                formato=data.get('formato', False),
                traducao=data.get('traducao', False),
                header_trailer=data.get('header_trailer', False),
                mail=data.get('mail', False),
                diagram_filename=data.get('diagram_filename')
            )

            db.session.add(profile)
            db.session.commit()
            return True

    except Exception as e:
        db.session.rollback()
        return False

def restore_ftp_config(data, record_id):
    """Restaura configuração FTP excluída"""
    try:
        # Validar integridade referencial - verificar se o perfil existe
        profile_id = data.get('perfil_id')
        if not profile_id:
            flash('ID do perfil não encontrado nos dados de restauração.', 'danger')
            return False

        profile = Perfil.query.filter_by(id_perfil=profile_id, is_deleted=False).first()
        if not profile:
            flash(f'Perfil com ID {profile_id} não existe ou foi deletado. Restauração de configuração FTP cancelada para manter integridade do banco.', 'warning')
            return False

        # Verificar se o perfil tem FTP habilitado
        if not profile.ftp:
            flash(f'Perfil "{profile.perfil}" não tem FTP habilitado. Restauração cancelada.', 'warning')
            return False

        ftp_config = FTP(
            id_perfil=profile_id,
            servidor=data.get('servidor'),
            porta=data.get('porta', 21),
            usuario=data.get('usuario'),
            senha=data.get('senha'),
            dir_local=data.get('dir_local'),
            dir_remoto=data.get('dir_remoto'),
            arquivo_local=data.get('arquivo_local'),
            arquivo_remoto=data.get('arquivo_remoto'),
            comando=data.get('comando'),
            zip=data.get('zip', False),
            crlf=data.get('crlf', False),
            rel=data.get('rel', False),
            bin=data.get('bin', False),
            dmz=data.get('dmz', False)
        )

        db.session.add(ftp_config)
        db.session.commit()
        return True

    except Exception as e:
        db.session.rollback()
        return False

def restore_scp_config(data, record_id):
    """Restaura configuração SCP excluída"""
    try:
        # Validar integridade referencial - verificar se o perfil existe
        profile_id = data.get('perfil_id')
        if not profile_id:
            flash('ID do perfil não encontrado nos dados de restauração.', 'danger')
            return False

        profile = Perfil.query.filter_by(id_perfil=profile_id, is_deleted=False).first()
        if not profile:
            flash(f'Perfil com ID {profile_id} não existe ou foi deletado. Restauração de configuração SCP cancelada para manter integridade do banco.', 'warning')
            return False

        # Verificar se o perfil tem SCP habilitado
        if not profile.scp:
            flash(f'Perfil "{profile.perfil}" não tem SCP habilitado. Restauração cancelada.', 'warning')
            return False

        scp_config = SCP(
            id_perfil=profile_id,
            servidor=data.get('servidor'),
            porta=data.get('porta', 22),
            usuario=data.get('usuario'),
            senha=data.get('senha'),
            ssh=data.get('chave_privada'),
            dir_remoto=data.get('diretorio_remoto', '/tmp')
        )

        db.session.add(scp_config)
        db.session.commit()
        return True

    except Exception as e:
        db.session.rollback()
        return False

def restore_http_config(data, record_id):
    """Restaura configuração HTTP excluída"""
    try:
        # Validar integridade referencial - verificar se o perfil existe
        profile_id = data.get('perfil_id')
        if not profile_id:
            flash('ID do perfil não encontrado nos dados de restauração.', 'danger')
            return False

        profile = Perfil.query.filter_by(id_perfil=profile_id, is_deleted=False).first()
        if not profile:
            flash(f'Perfil com ID {profile_id} não existe ou foi deletado. Restauração de configuração HTTP cancelada para manter integridade do banco.', 'warning')
            return False

        # Verificar se o perfil tem HTTP habilitado
        if not profile.http:
            flash(f'Perfil "{profile.perfil}" não tem HTTP habilitado. Restauração cancelada.', 'warning')
            return False

        http_config = HTTP(
            id_perfil=profile_id,
            dns=data.get('url_base'),
            metodo=data.get('metodo', 'POST'),
            prms=data.get('headers_personalizados'),
            usuario=data.get('usuario')
        )

        db.session.add(http_config)
        db.session.commit()
        return True

    except Exception as e:
        db.session.rollback()
        return False

def restore_s3_config(data, record_id):
    """Restaura configuração S3 excluída"""
    try:
        # Validar integridade referencial - verificar se o perfil existe
        profile_id = data.get('perfil_id')
        if not profile_id:
            flash('ID do perfil não encontrado nos dados de restauração.', 'danger')
            return False

        profile = Perfil.query.filter_by(id_perfil=profile_id, is_deleted=False).first()
        if not profile:
            flash(f'Perfil com ID {profile_id} não existe ou foi deletado. Restauração de configuração S3 cancelada para manter integridade do banco.', 'warning')
            return False

        # Verificar se o perfil tem S3 habilitado
        if not profile.s3:
            flash(f'Perfil "{profile.perfil}" não tem S3 habilitado. Restauração cancelada.', 'warning')
            return False

        s3_config = S3(
            id_perfil=profile_id,
            bucketname=data.get('bucket_name'),
            region=data.get('region'),
            accesskey=data.get('access_key'),
            secretkey=data.get('secret_key'),
            endpointurl=data.get('endpoint_url'),
            foldername=data.get('prefixo')
        )

        db.session.add(s3_config)
        db.session.commit()
        return True

    except Exception as e:
        db.session.rollback()
        return False

def restore_connect_direct_config(data, record_id):
    """Restaura configuração Connect:Direct excluída"""
    try:
        # Validar integridade referencial - verificar se o perfil existe
        profile_id = data.get('perfil_id')
        if not profile_id:
            flash('ID do perfil não encontrado nos dados de restauração.', 'danger')
            return False

        profile = Perfil.query.filter_by(id_perfil=profile_id, is_deleted=False).first()
        if not profile:
            flash(f'Perfil com ID {profile_id} não existe ou foi deletado. Restauração de configuração Connect:Direct cancelada para manter integridade do banco.', 'warning')
            return False

        # Verificar se o perfil tem Connect:Direct habilitado
        if not profile.cd:
            flash(f'Perfil "{profile.perfil}" não tem Connect:Direct habilitado. Restauração cancelada.', 'warning')
            return False

        cd_config = CD(
            id_perfil=profile_id,
            node=data.get('node'),
            tit=data.get('tit'),
            aut=data.get('aut'),
            dhd=data.get('dhd'),
            dst=data.get('dst'),
            dsn=data.get('dsn'),
            dcb=data.get('dcb'),
            codbanco=data.get('codbanco'),
            tsk=data.get('tsk'),
            job=data.get('job'),
            spc=data.get('spc'),
            dmz=data.get('dmz', True),
            disp=data.get('disp'),
            sysopts=data.get('sysopts'),
            opts=data.get('opts')
        )

        db.session.add(cd_config)
        db.session.commit()
        return True

    except Exception as e:
        db.session.rollback()
        return False

def restore_jasppion_config(data, record_id):
    """Restaura configuração JASPPION excluída"""
    try:
        # Validar integridade referencial - verificar se o perfil existe
        profile_id = data.get('perfil_id')
        if not profile_id:
            flash('ID do perfil não encontrado nos dados de restauração.', 'danger')
            return False

        profile = Perfil.query.filter_by(id_perfil=profile_id, is_deleted=False).first()
        if not profile:
            flash(f'Perfil com ID {profile_id} não existe ou foi deletado. Restauração de configuração JASPPION cancelada para manter integridade do banco.', 'warning')
            return False

        # Verificar se o perfil tem JASPPION habilitado
        if not profile.jasppion:
            flash(f'Perfil "{profile.perfil}" não tem JASPPION habilitado. Restauração cancelada.', 'warning')
            return False

        jasppion_config = Jasppion(
            id_perfil=profile_id,
            servidor=data.get('servidor'),
            porta=data.get('porta'),
            uri=data.get('uri'),
            app=data.get('codigo_participante'),
            logon=data.get('usuario'),
            programa=data.get('programa'),
            roscoe=data.get('roscoe')
        )

        db.session.add(jasppion_config)
        db.session.commit()
        return True

    except Exception as e:
        db.session.rollback()
        return False

def restore_user(data, record_id):
    """Restaura usuário excluído"""
    try:
        # Verifica se já existe usuário com mesmo username
        existing = User.query.filter_by(username=data.get('username')).first()
        if existing:
            flash(f'Já existe um usuário com o nome "{data.get("username")}".', 'warning')
            return False

        # Verifica se já existe usuário com mesmo email
        existing_email = User.query.filter_by(email=data.get('email')).first()
        if existing_email:
            flash(f'Já existe um usuário com o email "{data.get("email")}".', 'warning')
            return False

        user = User(
            username=data.get('username'),
            email=data.get('email'),
            password_hash=data.get('password_hash'),
            user_type=data.get('user_type', 'basico'),
            is_active=data.get('is_active', True),
            auth_type=data.get('auth_type', 'local'),
            ldap_dn=data.get('ldap_dn')
        )

        db.session.add(user)
        db.session.commit()
        return True

    except Exception as e:
        print(f"Erro na restauração do usuário: {str(e)}")
        db.session.rollback()
        return False

def get_quick_actions_for_profile(profile):
    """Retorna lista de ações rápidas para funcionalidades habilitadas sem registros"""
    quick_actions = []

    # Dicionário de mapeamento funcionalidade -> (modelo, nome, url_rota, ícone)
    functionalities = {
        'ftp': (FTP, 'FTP', 'create_ftp', 'fas fa-upload'),
        'scp': (SCP, 'SCP', 'create_scp', 'fas fa-shield-alt'),
        'cd': (CD, 'Connect:Direct', 'create_cd', 'fas fa-exchange-alt'),
        'http': (HTTP, 'HTTP', 'create_http', 'fas fa-globe'),
        'jasppion': (Jasppion, 'JASPPION', 'create_jasppion', 'fas fa-robot'),
        's3': (S3, 'S3', 'create_s3', 'fab fa-aws'),
        'mq': (MQ, 'MQ', 'create_mq', 'fas fa-comments'),
        'cmd': (CMD, 'CMD', 'create_cmd', 'fas fa-terminal'),
        'formato': (Formato, 'Formato', 'create_formato', 'fas fa-file-code'),
        'header_trailer': (HeaderTrailer, 'Header/Trailer', 'create_headertrailer', 'fas fa-file-alt'),
        'jcl': (JCL, 'JCL', 'create_jcl', 'fas fa-code'),
        'mail': (Mail, 'Mail', 'create_funcionalidades_mail', 'fas fa-envelope'),
        'prm': (PRM, 'PRM', 'create_prm', 'fas fa-sliders-h'),
        'traducao': (Traducao, 'Tradução', 'create_traducao', 'fas fa-language'),
        'ser': (SER, 'SER', 'create_ser', 'fas fa-server'),
    }

    for attr_name, (model_class, display_name, route_name, icon) in functionalities.items():
        # Verifica se a funcionalidade está habilitada no perfil
        if hasattr(profile, attr_name) and getattr(profile, attr_name):
            # Verifica se não há registros para esta funcionalidade
            existing_count = model_class.query.filter_by(
                id_perfil=profile.id_perfil,
                is_deleted=False
            ).count()

            if existing_count == 0:
                quick_actions.append({
                    'name': display_name,
                    'url': url_for(route_name, perfil_id=profile.id_perfil),
                    'icon': icon
                })

    return quick_actions

def restore_cmd_config(data, record_id):
    """Restaura configuração CMD excluída"""
    try:
        # Validar integridade referencial - verificar se o perfil existe
        profile_id = data.get('id_perfil')
        if not profile_id:
            flash('ID do perfil não encontrado nos dados de restauração.', 'danger')
            return False

        profile = Perfil.query.filter_by(id_perfil=profile_id, is_deleted=False).first()
        if not profile:
            flash(f'Perfil com ID {profile_id} não existe ou foi deletado. Restauração de configuração CMD cancelada para manter integridade do banco.', 'warning')
            return False

        # Verificar se o perfil tem CMD habilitado
        if not profile.cmd:
            flash(f'Perfil "{profile.perfil}" não tem CMD habilitado. Restauração cancelada.', 'warning')
            return False

        cmd_config = CMD(
            id_perfil=profile_id,
            nome=data.get('nome'),
            descricao=data.get('descricao'),
            comando=data.get('comando'),
            parametros=data.get('parametros')
        )

        db.session.add(cmd_config)
        db.session.commit()
        return True

    except Exception as e:
        db.session.rollback()
        return False

def restore_formato_config(data, record_id):
    """Restaura configuração Formato excluída"""
    try:
        # Validar integridade referencial - verificar se o perfil existe
        profile_id = data.get('id_perfil')
        if not profile_id:
            flash('ID do perfil não encontrado nos dados de restauração.', 'danger')
            return False

        profile = Perfil.query.filter_by(id_perfil=profile_id, is_deleted=False).first()
        if not profile:
            flash(f'Perfil com ID {profile_id} não existe ou foi deletado. Restauração de configuração Formato cancelada para manter integridade do banco.', 'warning')
            return False

        # Verificar se o perfil tem Formato habilitado
        if not profile.formato:
            flash(f'Perfil "{profile.perfil}" não tem Formato habilitado. Restauração cancelada.', 'warning')
            return False

        formato_config = Formato(
            id_perfil=profile_id,
            nome=data.get('nome'),
            descricao=data.get('descricao'),
            formato=data.get('formato'),
            delimitador=data.get('delimitador')
        )

        db.session.add(formato_config)
        db.session.commit()
        return True

    except Exception as e:
        db.session.rollback()
        return False

def restore_jcl_config(data, record_id):
    """Restaura configuração JCL excluída"""
    try:
        # Validar integridade referencial - verificar se o perfil existe
        profile_id = data.get('id_perfil')
        if not profile_id:
            flash('ID do perfil não encontrado nos dados de restauração.', 'danger')
            return False

        profile = Perfil.query.filter_by(id_perfil=profile_id, is_deleted=False).first()
        if not profile:
            flash(f'Perfil com ID {profile_id} não existe ou foi deletado. Restauração de configuração JCL cancelada para manter integridade do banco.', 'warning')
            return False

        # Verificar se o perfil tem JCL habilitado
        if not profile.jcl:
            flash(f'Perfil "{profile.perfil}" não tem JCL habilitado. Restauração cancelada.', 'warning')
            return False

        jcl_config = JCL(
            id_perfil=profile_id,
            nome=data.get('nome'),
            descricao=data.get('descricao'),
            jcl=data.get('jcl'),
            parametros=data.get('parametros')
        )

        db.session.add(jcl_config)
        db.session.commit()
        return True

    except Exception as e:
        db.session.rollback()
        return False

def restore_prm_config(data, record_id):
    """Restaura configuração PRM excluída"""
    try:
        # Validar integridade referencial - verificar se o perfil existe
        profile_id = data.get('id_perfil')
        if not profile_id:
            flash('ID do perfil não encontrado nos dados de restauração.', 'danger')
            return False

        profile = Perfil.query.filter_by(id_perfil=profile_id, is_deleted=False).first()
        if not profile:
            flash(f'Perfil com ID {profile_id} não existe ou foi deletado. Restauração de configuração PRM cancelada para manter integridade do banco.', 'warning')
            return False

        # Verificar se o perfil tem PRM habilitado
        if not profile.prm:
            flash(f'Perfil "{profile.perfil}" não tem PRM habilitado. Restauração cancelada.', 'warning')
            return False

        prm_config = PRM(
            id_perfil=profile_id,
            nome=data.get('nome'),
            descricao=data.get('descricao'),
            parametro=data.get('parametro'),
            valor=data.get('valor')
        )

        db.session.add(prm_config)
        db.session.commit()
        return True

    except Exception as e:
        db.session.rollback()
        return False

def restore_traducao_config(data, record_id):
    """Restaura configuração Tradução excluída"""
    try:
        # Validar integridade referencial - verificar se o perfil existe
        profile_id = data.get('id_perfil')
        if not profile_id:
            flash('ID do perfil não encontrado nos dados de restauração.', 'danger')
            return False

        profile = Perfil.query.filter_by(id_perfil=profile_id, is_deleted=False).first()
        if not profile:
            flash(f'Perfil com ID {profile_id} não existe ou foi deletado. Restauração de configuração Tradução cancelada para manter integridade do banco.', 'warning')
            return False

        # Verificar se o perfil tem Tradução habilitado
        if not profile.traducao:
            flash(f'Perfil "{profile.perfil}" não tem Tradução habilitado. Restauração cancelada.', 'warning')
            return False

        traducao_config = Traducao(
            id_perfil=profile_id,
            nome=data.get('nome'),
            descricao=data.get('descricao'),
            origem=data.get('origem'),
            destino=data.get('destino'),
            mapeamento=data.get('mapeamento')
        )

        db.session.add(traducao_config)
        db.session.commit()
        return True

    except Exception as e:
        db.session.rollback()
        return False

def restore_ser_config(data, record_id):
    """Restaura configuração SER excluída"""
    try:
        # Validar integridade referencial - verificar se o perfil existe
        profile_id = data.get('id_perfil')
        if not profile_id:
            flash('ID do perfil não encontrado nos dados de restauração.', 'danger')
            return False

        profile = Perfil.query.filter_by(id_perfil=profile_id, is_deleted=False).first()
        if not profile:
            flash(f'Perfil com ID {profile_id} não existe ou foi deletado. Restauração de configuração SER cancelada para manter integridade do banco.', 'warning')
            return False

        # Verificar se o perfil tem SER habilitado
        if not profile.ser:
            flash(f'Perfil "{profile.perfil}" não tem SER habilitado. Restauração cancelada.', 'warning')
            return False

        ser_config = SER(
            id_perfil=profile_id,
            nome=data.get('nome'),
            descricao=data.get('descricao'),
            servico=data.get('servico'),
            endpoint=data.get('endpoint')
        )

        db.session.add(ser_config)
        db.session.commit()
        return True

    except Exception as e:
        db.session.rollback()
        return False

def restore_header_trailer_config(data, record_id):
    """Restaura configuração Header/Trailer excluída"""
    try:
        # Validar integridade referencial - verificar se o perfil existe
        profile_id = data.get('id_perfil')
        if not profile_id:
            flash('ID do perfil não encontrado nos dados de restauração.', 'danger')
            return False

        profile = Perfil.query.filter_by(id_perfil=profile_id, is_deleted=False).first()
        if not profile:
            flash(f'Perfil com ID {profile_id} não existe ou foi deletado. Restauração de configuração Header/Trailer cancelada para manter integridade do banco.', 'warning')
            return False

        # Verificar se o perfil tem Header/Trailer habilitado
        if not profile.header_trailer:
            flash(f'Perfil "{profile.perfil}" não tem Header/Trailer habilitado. Restauração cancelada.', 'warning')
            return False

        ht_config = HeaderTrailer(
            id_perfil=profile_id,
            nome=data.get('nome'),
            descricao=data.get('descricao'),
            header=data.get('header'),
            trailer=data.get('trailer')
        )

        db.session.add(ht_config)
        db.session.commit()
        return True

    except Exception as e:
        db.session.rollback()
        return False

def restore_mail_config(data, record_id):
    """Restaura configuração Mail excluída"""
    try:
        # Validar integridade referencial - verificar se o perfil existe
        profile_id = data.get('id_perfil')
        if not profile_id:
            flash('ID do perfil não encontrado nos dados de restauração.', 'danger')
            return False

        profile = Perfil.query.filter_by(id_perfil=profile_id, is_deleted=False).first()
        if not profile:
            flash(f'Perfil com ID {profile_id} não existe ou foi deletado. Restauração de configuração Mail cancelada para manter integridade do banco.', 'warning')
            return False

        # Verificar se o perfil tem Mail habilitado
        if not profile.mail:
            flash(f'Perfil "{profile.perfil}" não tem Mail habilitado. Restauração cancelada.', 'warning')
            return False

        mail_config = Mail(
            id_perfil=profile_id,
            nome=data.get('nome'),
            descricao=data.get('descricao'),
            smtp_server=data.get('smtp_server'),
            smtp_port=data.get('smtp_port'),
            usuario=data.get('usuario'),
            senha=data.get('senha'),
            remetente=data.get('remetente'),
            destinatario=data.get('destinatario')
        )

        db.session.add(mail_config)
        db.session.commit()
        return True

    except Exception as e:
        db.session.rollback()
        return False

def restore_faq(data, record_id):
    """Restaura FAQ excluído"""
    try:
        # Verifica se já existe FAQ com mesma pergunta na mesma categoria
        existing = FAQ.query.filter_by(
            categoria=data.get('categoria'),
            pergunta=data.get('pergunta'),
            is_deleted=False
        ).first()
        if existing:
            flash(f'Já existe uma FAQ com a pergunta "{data.get("pergunta")}" na categoria "{data.get("categoria")}".', 'warning')
            return False

        # Restaura o FAQ deletado marcando como não deletado e limpando deleted_data
        faq = FAQ.query.get(record_id)
        if faq:
            faq.is_deleted = False
            faq.deleted_data = None
            db.session.commit()
            return True
        else:
            # Se o registro não existe mais, cria um novo
            faq = FAQ(
                categoria=data.get('categoria'),
                pergunta=data.get('pergunta'),
                resposta=data.get('resposta'),
                imagem_filename=data.get('imagem_filename')
            )

            db.session.add(faq)
            db.session.commit()
            return True

    except Exception as e:
        print(f"Erro na restauração do FAQ: {str(e)}")
        db.session.rollback()
        return False

def restore_ftpusers(data, record_id):
    """Restaura configuração FTP Users excluída"""
    try:
        # Verifica se já existe usuário FTP com mesmo nome
        existing = FTPUsers.query.filter_by(usuario=data.get('usuario'), is_deleted=False).first()
        if existing:
            flash(f'Já existe um usuário FTP com o nome "{data.get("usuario")}".', 'warning')
            return False

        # Restaura o registro deletado
        ftpuser = FTPUsers.query.get(record_id)
        if ftpuser and ftpuser.is_deleted:
            ftpuser.is_deleted = False
            ftpuser.usuario = data.get('usuario', '')
            ftpuser.mf_unit = data.get('mf_unit', '')
            db.session.commit()
            return True
        else:
            # Se o registro não existe mais, cria um novo
            ftpuser = FTPUsers(
                usuario=data.get('usuario', ''),
                mf_unit=data.get('mf_unit', '')
            )
            db.session.add(ftpuser)
            db.session.commit()
            return True

    except Exception as e:
        print(f"Erro na restauração do FTP Users: {str(e)}")
        db.session.rollback()
        return False

def restore_mailgroup(data, record_id):
    """Restaura configuração Mail Group excluída"""
    try:
        # Verifica se já existe grupo com mesmo nome
        existing = MailGroup.query.filter_by(grupo=data.get('grupo'), is_deleted=False).first()
        if existing:
            flash(f'Já existe um grupo de mail com o nome "{data.get("grupo")}".', 'warning')
            return False

        # Restaura o registro deletado
        mailgroup = MailGroup.query.get(record_id)
        if mailgroup and mailgroup.is_deleted:
            mailgroup.is_deleted = False
            mailgroup.grupo = data.get('grupo', '')
            mailgroup.dst = data.get('dst', '')
            db.session.commit()
            return True
        else:
            # Se o registro não existe mais, cria um novo
            mailgroup = MailGroup(
                grupo=data.get('grupo', ''),
                dst=data.get('dst', '')
            )
            db.session.add(mailgroup)
            db.session.commit()
            return True

    except Exception as e:
        print(f"Erro na restauração do Mail Group: {str(e)}")
        db.session.rollback()
        return False

def restore_roscoe(data, record_id):
    """Restaura configuração Roscoe excluída"""
    try:
        # Verifica se já existe configuração com mesma chave
        existing = Roscoe.query.filter_by(chave=data.get('chave'), is_deleted=False).first()
        if existing:
            flash(f'Já existe uma configuração Roscoe com a chave "{data.get("chave")}".', 'warning')
            return False

        # Restaura o registro deletado
        roscoe = Roscoe.query.get(record_id)
        if roscoe and roscoe.is_deleted:
            roscoe.is_deleted = False
            roscoe.chave = data.get('chave', '')
            roscoe.dst = data.get('dst', '')
            db.session.commit()
            return True
        else:
            # Se o registro não existe mais, cria um novo
            roscoe = Roscoe(
                chave=data.get('chave', ''),
                dst=data.get('dst', '')
            )
            db.session.add(roscoe)
            db.session.commit()
            return True

    except Exception as e:
        print(f"Erro na restauração do Roscoe: {str(e)}")
        db.session.rollback()
        return False

def restore_mq_config(data, record_id):
    """Restaura configuração MQ excluída"""
    try:
        # Validar integridade referencial - verificar se o perfil existe
        profile_id = data.get('perfil_id')
        if not profile_id:
            flash('ID do perfil não encontrado nos dados de restauração.', 'danger')
            return False

        profile = Perfil.query.filter_by(id_perfil=profile_id, is_deleted=False).first()
        if not profile:
            flash(f'Perfil com ID {profile_id} não existe ou foi deletado. Restauração de configuração MQ cancelada para manter integridade do banco.', 'warning')
            return False

        # Verificar se o perfil tem MQ habilitado
        if not profile.mq:
            flash(f'Perfil "{profile.perfil}" não tem MQ habilitado. Restauração cancelada.', 'warning')
            return False

        mq_config = MQ(
            id_perfil=profile_id,
            hostname=data.get('hostname'),
            port=data.get('port', 1414),
            channel=data.get('channel'),
            userid=data.get('userid'),
            passwd=data.get('passwd'),
            qmgr=data.get('qmgr'),
            qname=data.get('qname'),
            action=data.get('action'),
            gettype=data.get('gettype'),
            msgtype=data.get('msgtype'),
            msgid=data.get('msgid'),
            ccsid=data.get('ccsid'),
            ttl=data.get('ttl'),
            ssl=data.get('ssl', False),
            tls=data.get('tls'),
            cert=data.get('cert'),
            mail=data.get('mail', False),
            mailmsg=data.get('mailmsg'),
            mailass=data.get('mailass'),
            maildest=data.get('maildest'),
            mailanexo=data.get('mailanexo', False)
        )

        db.session.add(mq_config)
        db.session.commit()
        return True

    except Exception as e:
        db.session.rollback()
        return False

# Configuration
@app.route('/configuracoes')
@login_required
def configuration():
    app.logger.info(f'Usuário {current_user.username} acessando configurações. Tipo: {current_user.user_type}')
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        app.logger.warning(f'Acesso negado às configurações para usuário {current_user.username}')
        return redirect(url_for('dashboard'))

    stats = get_statistics()

    # Passar variáveis de ambiente para o template
    env_vars = {
        'ORACLE_HOST': os.environ.get('ORACLE_HOST', 'ec2-52-202-108-33.compute-1.amazonaws.com'),
        'ORACLE_PORT': os.environ.get('ORACLE_PORT', '1521'),
        'ORACLE_DATABASE': os.environ.get('ORACLE_DATABASE', 'orcl'),
        'ORACLE_USER': os.environ.get('ORACLE_USER', 'oracleuser'),
    }

    return render_template('config/index.html', stats=stats, env_vars=env_vars)

# Alias para a rota de configurações
@app.route('/configuracoes/index')
@login_required
def config_index():
    return configuration()

@app.route('/configuracoes/database', methods=['GET', 'POST'])
@login_required
def database_configuration():
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('dashboard'))

    form = DatabaseConfigForm()

    if form.validate_on_submit():
        config_data = {
            'oracle_host': form.oracle_host.data or '',
            'oracle_port': form.oracle_port.data or '',
            'oracle_service': form.oracle_service.data or '',
            'oracle_username': form.oracle_username.data or '',
            'oracle_password': form.oracle_password.data or '',
            'oracle_schema': form.oracle_schema.data or ''
        }

        try:
            save_database_configs(config_data)
            log_audit('UPDATE', 'system_config', None, 'Configurações de banco de dados atualizadas')
            flash('Configurações de banco de dados salvas com sucesso!', 'success')
            return redirect(url_for('database_configuration'))
        except Exception as e:
            flash(f'Erro ao salvar configurações: {str(e)}', 'danger')

    # Load existing configurations
    existing_configs = get_database_configs()
    form.oracle_host.data = existing_configs.get('oracle_host', '')
    form.oracle_port.data = existing_configs.get('oracle_port', '')
    form.oracle_service.data = existing_configs.get('oracle_service', '')
    form.oracle_username.data = existing_configs.get('oracle_username', '')
    form.oracle_password.data = existing_configs.get('oracle_password', '')
    form.oracle_schema.data = existing_configs.get('oracle_schema', '')

    # Build connection strings for display
    connection_strings = build_connection_strings()

    return render_template('config/database.html', form=form, connection_strings=connection_strings)

@app.route('/configuracoes/servidor', methods=['GET', 'POST'])
@login_required
def server_configuration():
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('dashboard'))

    form = ServerConfigForm()

    if form.validate_on_submit():
        config_data = {
            'server_name': form.server_name.data or '',
            'server_description': form.server_description.data or '',
            'maintenance_mode': form.maintenance_mode.data,
            'debug_mode': form.debug_mode.data,
            'max_upload_size': form.max_upload_size.data or 16,
            'session_timeout': form.session_timeout.data or 30,
            'max_concurrent_users': form.max_concurrent_users.data or 100,
            'log_level': form.log_level.data or 'INFO',
            'log_retention_days': form.log_retention_days.data or 30,
            'auto_backup': form.auto_backup.data,
            'backup_frequency': form.backup_frequency.data or 'weekly',
            'backup_retention': form.backup_retention.data or 7,
            'smtp_server': form.smtp_server.data or '',
            'smtp_port': form.smtp_port.data or 587,
            'smtp_username': form.smtp_username.data or '',
            'smtp_password': form.smtp_password.data or '',
            'smtp_use_tls': form.smtp_use_tls.data,
            'admin_email': form.admin_email.data or ''
        }

        try:
            save_server_configs(config_data)
            log_audit('UPDATE', 'system_config', None, 'Configurações do servidor atualizadas')
            flash('Configurações do servidor salvas com sucesso!', 'success')
            return redirect(url_for('server_configuration'))
        except Exception as e:
            flash(f'Erro ao salvar configurações: {str(e)}', 'danger')

    # Load existing configurations
    existing_configs = get_server_configs()
    form.server_name.data = existing_configs.get('server_name', '')
    form.server_description.data = existing_configs.get('server_description', '')
    form.maintenance_mode.data = existing_configs.get('maintenance_mode', False)
    form.debug_mode.data = existing_configs.get('debug_mode', False)
    form.max_upload_size.data = existing_configs.get('max_upload_size', 16)
    form.session_timeout.data = existing_configs.get('session_timeout', 30)
    form.max_concurrent_users.data = existing_configs.get('max_concurrent_users', 100)
    form.log_level.data = existing_configs.get('log_level', 'INFO')
    form.log_retention_days.data = existing_configs.get('log_retention_days', 30)
    form.auto_backup.data = existing_configs.get('auto_backup', False)
    form.backup_frequency.data = existing_configs.get('backup_frequency', 'weekly')
    form.backup_retention.data = existing_configs.get('backup_retention', 7)
    form.smtp_server.data = existing_configs.get('smtp_server', '')
    form.smtp_port.data = existing_configs.get('smtp_port', 587)
    form.smtp_username.data = existing_configs.get('smtp_username', '')
    form.smtp_password.data = existing_configs.get('smtp_password', '')
    form.smtp_use_tls.data = existing_configs.get('smtp_use_tls', True)
    form.admin_email.data = existing_configs.get('admin_email', '')

    return render_template('config/server.html', form=form)



@app.route('/configuracoes/seguranca', methods=['GET', 'POST'])
@login_required
def security_configuration():
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('dashboard'))

    form = SecurityConfigForm()

    if form.validate_on_submit():
        config_data = {
            'min_password_length': form.min_password_length.data or 8,
            'require_uppercase': form.require_uppercase.data,
            'require_lowercase': form.require_lowercase.data,
            'require_numbers': form.require_numbers.data,
            'require_special_chars': form.require_special_chars.data,
            'password_expiry_days': form.password_expiry_days.data or 90,
            'max_login_attempts': form.max_login_attempts.data or 5,
            'account_lockout_duration': form.account_lockout_duration.data or 15,
            'force_password_change': form.force_password_change.data,
            'audit_login_success': form.audit_login_success.data,
            'audit_login_failure': form.audit_login_failure.data,
            'audit_data_changes': form.audit_data_changes.data,
            'audit_file_operations': form.audit_file_operations.data,
            'audit_configuration_changes': form.audit_configuration_changes.data,
            'allow_concurrent_sessions': form.allow_concurrent_sessions.data,
            'ip_whitelist': form.ip_whitelist.data or '',
            'block_suspicious_ips': form.block_suspicious_ips.data,
            'secure_cookies': form.secure_cookies.data,
            'httponly_cookies': form.httponly_cookies.data,
            'same_site_cookies': form.same_site_cookies.data or 'Lax',
            'enable_csrf_protection': form.enable_csrf_protection.data,
            'rate_limiting': form.rate_limiting.data,
            'max_requests_per_minute': form.max_requests_per_minute.data or 60,
            'password_hash_algorithm': form.password_hash_algorithm.data or 'pbkdf2',
            'file_encryption': form.file_encryption.data,
            'encryption_key_rotation_days': form.encryption_key_rotation_days.data or 90
        }

        try:
            save_security_configs(config_data)
            log_audit('UPDATE', 'system_config', None, 'Configurações de segurança atualizadas')
            flash('Configurações de segurança salvas com sucesso!', 'success')
            return redirect(url_for('security_configuration'))
        except Exception as e:
            flash(f'Erro ao salvar configurações: {str(e)}', 'danger')

    # Load existing configurations
    existing_configs = get_security_configs()
    form.min_password_length.data = existing_configs.get('min_password_length', 8)
    form.require_uppercase.data = existing_configs.get('require_uppercase', False)
    form.require_lowercase.data = existing_configs.get('require_lowercase', False)
    form.require_numbers.data = existing_configs.get('require_numbers', False)
    form.require_special_chars.data = existing_configs.get('require_special_chars', False)
    form.password_expiry_days.data = existing_configs.get('password_expiry_days', 90)
    form.max_login_attempts.data = existing_configs.get('max_login_attempts', 5)
    form.account_lockout_duration.data = existing_configs.get('account_lockout_duration', 15)
    form.force_password_change.data = existing_configs.get('force_password_change', False)
    form.audit_login_success.data = existing_configs.get('audit_login_success', True)
    form.audit_login_failure.data = existing_configs.get('audit_login_failure', True)
    form.audit_data_changes.data = existing_configs.get('audit_data_changes', True)
    form.audit_file_operations.data = existing_configs.get('audit_file_operations', True)
    form.audit_configuration_changes.data = existing_configs.get('audit_configuration_changes', True)
    form.allow_concurrent_sessions.data = existing_configs.get('allow_concurrent_sessions', True)
    form.ip_whitelist.data = existing_configs.get('ip_whitelist', '')
    form.block_suspicious_ips.data = existing_configs.get('block_suspicious_ips', False)
    form.secure_cookies.data = existing_configs.get('secure_cookies', True)
    form.httponly_cookies.data = existing_configs.get('httponly_cookies', True)
    form.same_site_cookies.data = existing_configs.get('same_site_cookies', 'Lax')
    form.enable_csrf_protection.data = existing_configs.get('enable_csrf_protection', True)
    form.rate_limiting.data = existing_configs.get('rate_limiting', False)
    form.max_requests_per_minute.data = existing_configs.get('max_requests_per_minute', 60)
    form.password_hash_algorithm.data = existing_configs.get('password_hash_algorithm', 'pbkdf2')
    form.file_encryption.data = existing_configs.get('file_encryption', False)
    form.encryption_key_rotation_days.data = existing_configs.get('encryption_key_rotation_days', 90)

    return render_template('config/security.html', form=form)

# Functionality routes - CMD
@app.route('/funcionalidades/cmd')
@login_required
def list_cmd():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    search = request.args.get('search', '', type=str)

    query = db.session.query(CMD, Perfil).join(Perfil).filter(CMD.is_deleted == False)

    if search:
        search_pattern = f'%{search}%'
        query = query.filter(or_(
            Perfil.perfil.ilike(search_pattern),
            CMD.comando.ilike(search_pattern)
        ))

    configs = query.order_by(Perfil.perfil).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return render_template('functionalities/cmd.html', configs=configs, search=search)

@app.route('/funcionalidades/cmd/novo', methods=['GET', 'POST'])
@login_required
def create_cmd():
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_cmd'))

    form = CMDForm()
    # Populate choices for perfil_id field
    perfis_cmd = Perfil.query.filter_by(cmd=True, is_deleted=False).all()
    form.perfil_id.choices = [(p.id_perfil, p.perfil) for p in perfis_cmd]

    # Pré-selecionar perfil (recém-criado ou visualizado)
    preselect_profile_id = session.get('last_created_profile_id') or session.get('current_viewing_profile_id')
    if preselect_profile_id and any(p.id_perfil == preselect_profile_id for p in perfis_cmd):
        form.perfil_id.data = preselect_profile_id
        # Remover apenas o perfil recém-criado da sessão após usar
        session.pop('last_created_profile_id', None)

    if form.validate_on_submit():
        perfil = Perfil.query.get(form.perfil_id.data)
        if not perfil or not perfil.cmd or perfil.is_deleted:
            flash('Perfil não permite configuração CMD.', 'danger')
            return redirect(url_for('list_cmd'))

        cmd_config = CMD(id_perfil=form.perfil_id.data)
        form.populate_obj(cmd_config)

        db.session.add(cmd_config)
        db.session.commit()

        log_audit('CREATE', 'tb_cmd', cmd_config.id_cmd, f'Configuração CMD criada para perfil: {perfil.perfil}')
        flash('Configuração CMD criada com sucesso!', 'success')
        return redirect(url_for('list_cmd'))

    return render_template('functionalities/cmd_form.html', form=form, title='Nova Configuração CMD')

@app.route('/funcionalidades/cmd/<int:id>/view')
@login_required
def view_cmd_config(id):
    cmd_config = CMD.query.get_or_404(id)
    if cmd_config.is_deleted:
        abort(404)

    config_data = {
        'id': cmd_config.id_cmd,
        'perfil': cmd_config.perfil.perfil,
        'comando': cmd_config.comando or ''
    }
    return jsonify(config_data)

@app.route('/funcionalidades/cmd/<int:id>/editar', methods=['GET', 'POST'])
@login_required
def edit_cmd(id):
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_cmd'))

    cmd_config = CMD.query.get_or_404(id)
    if cmd_config.is_deleted:
        abort(404)

    form = CMDForm(obj=cmd_config)
    # Populate choices for perfil_id field
    form.perfil_id.choices = [(p.id_perfil, p.perfil) for p in Perfil.query.filter_by(cmd=True, is_deleted=False).all()]
    form.perfil_id.data = cmd_config.id_perfil

    if form.validate_on_submit():
        form.populate_obj(cmd_config)
        db.session.commit()

        log_audit('UPDATE', 'tb_cmd', id, f'Configuração CMD editada para perfil: {cmd_config.perfil.perfil}')
        flash('Configuração CMD atualizada com sucesso!', 'success')

        # Check if coming from advanced search
        if request.referrer and 'busca-avavançada' in request.referrer:
            return redirect(url_for('advanced_search'))
        return redirect(url_for('list_cmd'))

    return render_template('functionalities/cmd_form.html', form=form, cmd_config=cmd_config, title='Editar Configuração CMD')

@app.route('/funcionalidades/cmd/<int:id>/deletar', methods=['POST'])
@login_required
def delete_cmd(id):
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_cmd'))

    cmd_config = CMD.query.get_or_404(id)
    if cmd_config.is_deleted:
        abort(404)

    cmd_config.is_deleted = True
    db.session.commit()

    log_audit('DELETE', 'tb_cmd', id, f'Configuração CMD deletada para perfil: {cmd_config.perfil.perfil}')
    flash('Configuração CMD deletada com sucesso!', 'success')
    return redirect(url_for('list_cmd'))

# Formato routes
@app.route('/funcionalidades/formato')
@login_required
def list_formato():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    search = request.args.get('search', '', type=str)

    query = db.session.query(Formato, Perfil).join(Perfil).filter(Formato.is_deleted == False)

    if search:
        search_pattern = f'%{search}%'
        query = query.filter(or_(
            Perfil.perfil.ilike(search_pattern),
            Formato.de.ilike(search_pattern),
            Formato.para.ilike(search_pattern)
        ))

    configs = query.order_by(Perfil.perfil).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return render_template('functionalities/formato.html', configs=configs, search=search)

@app.route('/funcionalidades/formato/novo', methods=['GET', 'POST'])
@login_required
def create_formato():
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_formato'))

    form = FormatoForm()
    # Populate choices for perfil_id field
    perfis_formato = Perfil.query.filter_by(formato=True, is_deleted=False).all()
    form.perfil_id.choices = [(p.id_perfil, p.perfil) for p in perfis_formato]

    # Pré-selecionar perfil (recém-criado ou visualizado)
    preselect_profile_id = session.get('last_created_profile_id') or session.get('current_viewing_profile_id')
    if preselect_profile_id and any(p.id_perfil == preselect_profile_id for p in perfis_formato):
        form.perfil_id.data = preselect_profile_id
        # Remover apenas o perfil recém-criado da sessão após usar
        session.pop('last_created_profile_id', None)

    if form.validate_on_submit():
        perfil = Perfil.query.get(form.perfil_id.data)
        if not perfil or not perfil.formato or perfil.is_deleted:
            flash('Perfil não permite configuração Formato.', 'danger')
            return redirect(url_for('list_formato'))

        formato_config = Formato(id_perfil=form.perfil_id.data)
        form.populate_obj(formato_config)

        db.session.add(formato_config)
        db.session.commit()

        log_audit('CREATE', 'tb_formato', formato_config.id_formato, f'Configuração Formato criada para perfil: {perfil.perfil}')
        flash('Configuração Formato criada com sucesso!', 'success')
        return redirect(url_for('list_formato'))

    return render_template('functionalities/formato_form.html', form=form, title='Nova Configuração Formato')

@app.route('/funcionalidades/formato/<int:id>/view')
@login_required
def view_formato_config(id):
    formato_config = Formato.query.get_or_404(id)
    if formato_config.is_deleted:
        abort(404)

    config_data = {
        'id': formato_config.id_formato,
        'perfil': formato_config.perfil.perfil,
        'de': formato_config.de or '',
        'para': formato_config.para or ''
    }
    return jsonify(config_data)

@app.route('/funcionalidades/formato/<int:id>/editar', methods=['GET', 'POST'])
@login_required
def edit_formato(id):
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_formato'))

    formato_config = Formato.query.get_or_404(id)
    if formato_config.is_deleted:
        abort(404)

    form = FormatoForm(obj=formato_config)
    # Populate choices for perfil_id field
    form.perfil_id.choices = [(p.id_perfil, p.perfil) for p in Perfil.query.filter_by(formato=True, is_deleted=False).all()]
    form.perfil_id.data = formato_config.id_perfil

    if form.validate_on_submit():
        form.populate_obj(formato_config)
        db.session.commit()

        log_audit('UPDATE', 'tb_formato', id, f'Configuração Formato editada para perfil: {formato_config.perfil.perfil}')
        flash('Configuração Formato atualizada com sucesso!', 'success')

        # Check if coming from advanced search
        if request.referrer and 'busca-avancada' in request.referrer:
            return redirect(url_for('advanced_search'))
        return redirect(url_for('list_formato'))

    return render_template('functionalities/formato_form.html', form=form, formato_config=formato_config, title='Editar Configuração Formato')

@app.route('/funcionalidades/formato/<int:id>/deletar', methods=['POST'])
@login_required
def delete_formato(id):
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_formato'))

    formato_config = Formato.query.get_or_404(id)
    if formato_config.is_deleted:
        abort(404)

    formato_config.is_deleted = True
    db.session.commit()

    log_audit('DELETE', 'tb_formato', id, f'Configuração Formato deletada para perfil: {formato_config.perfil.perfil}')
    flash('Configuração Formato deletada com sucesso!', 'success')
    return redirect(url_for('list_formato'))

# Mail routes (Funcionalidades)
@app.route('/funcionalidades/mail')
@login_required
def list_funcionalidades_mail():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    search = request.args.get('search', '', type=str)

    query = db.session.query(Mail, Perfil).join(Perfil).filter(Mail.is_deleted == False)

    if search:
        search_pattern = f'%{search}%'
        query = query.filter(or_(
            Perfil.perfil.ilike(search_pattern),
            Mail.tit.ilike(search_pattern),
            Mail.dest.ilike(search_pattern)
        ))

    configs = query.order_by(Perfil.perfil).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return render_template('functionalities/mail.html', configs=configs, search=search)

@app.route('/funcionalidades/mail/novo', methods=['GET', 'POST'])
@login_required
def create_funcionalidades_mail():
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_funcionalidades_mail'))

    form = MailForm()
    # Populate choices for perfil_id field
    form.perfil_id.choices = [(p.id_perfil, p.perfil) for p in Perfil.query.filter_by(mail=True, is_deleted=False).all()]

    if form.validate_on_submit():
        perfil = Perfil.query.get(form.perfil_id.data)
        if not perfil or not perfil.mail or perfil.is_deleted:
            flash('Perfil não permite configuração Mail.', 'danger')
            return redirect(url_for('list_funcionalidades_mail'))

        mail_config = Mail(id_perfil=form.perfil_id.data)
        form.populate_obj(mail_config)

        db.session.add(mail_config)
        db.session.commit()

        log_audit('CREATE', 'tb_mail', mail_config.id_mail, f'Configuração Mail criada para perfil: {perfil.perfil}')
        flash('Configuração Mail criada com sucesso!', 'success')
        return redirect(url_for('list_funcionalidades_mail'))

    return render_template('functionalities/mail_form.html', form=form, title='Nova Configuração Mail')

# Additional routes for funcionalidades/mail
@app.route('/funcionalidades/mail/<int:id>/view')
@login_required
def view_funcionalidades_mail_config(id):
    mail_config = Mail.query.get_or_404(id)
    if mail_config.is_deleted:
        abort(404)

    config_data = {
        'id': mail_config.id_mail,
        'perfil': mail_config.perfil.perfil,
        'tit': mail_config.tit or '',
        'dest': mail_config.dest or '',
        'anexo': mail_config.anexo or '',
        'msg': mail_config.msg or ''
    }
    return jsonify(config_data)

@app.route('/funcionalidades/mail/<int:id>/editar', methods=['GET', 'POST'])
@login_required
def edit_funcionalidades_mail(id):
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_funcionalidades_mail'))

    mail_config = Mail.query.get_or_404(id)
    if mail_config.is_deleted:
        abort(404)

    form = MailForm(obj=mail_config)
    # Populate choices for perfil_id field
    form.perfil_id.choices = [(p.id_perfil, p.perfil) for p in Perfil.query.filter_by(mail=True, is_deleted=False).all()]
    form.perfil_id.data = mail_config.id_perfil

    if form.validate_on_submit():
        form.populate_obj(mail_config)
        db.session.commit()

        log_audit('UPDATE', 'tb_mail', id, f'Configuração Mail editada para perfil: {mail_config.perfil.perfil}')
        flash('Configuração Mail atualizada com sucesso!', 'success')

        # Check if coming from advanced search
        if request.referrer and 'busca-avancada' in request.referrer:
            return redirect(url_for('advanced_search'))
        return redirect(url_for('list_funcionalidades_mail'))

    return render_template('functionalities/mail_form.html', form=form, mail_config=mail_config, title='Editar Configuração Mail')

@app.route('/funcionalidades/mail/<int:id>/deletar', methods=['POST'])
@login_required
def delete_funcionalidades_mail(id):
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_funcionalidades_mail'))

    mail_config = Mail.query.get_or_404(id)
    if mail_config.is_deleted:
        abort(404)

    mail_config.is_deleted = True
    db.session.commit()

    log_audit('DELETE', 'tb_mail', id, f'Configuração Mail deletada para perfil: {mail_config.perfil.perfil}')
    flash('Configuração Mail deletada com sucesso!', 'success')
    return redirect(url_for('list_funcionalidades_mail'))

# FTP Users routes (Notificações)
# FTP Users routes
@app.route('/notificacoes/ftpusers')
@login_required
def list_ftpusers():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    search = request.args.get('search', '', type=str)

    query = FTPUsers.query.filter(FTPUsers.is_deleted == False)

    if search:
        search_pattern = f'%{search}%'
        query = query.filter(FTPUsers.usuario.ilike(search_pattern))

    configs = query.order_by(FTPUsers.usuario).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return render_template('notifications/ftpusers.html', configs=configs, search=search)

@app.route('/notificacoes/ftpusers/novo', methods=['GET', 'POST'])
@login_required
def create_ftpusers():
    if not current_user.is_advanced():
        flash('Acesso negado. Você precisa de permissões avançadas para acessar esta funcionalidade.', 'danger')
        return redirect(url_for('list_ftpusers'))

    form = FTPUsersForm()
    if form.validate_on_submit():
        ftpuser_config = FTPUsers()
        form.populate_obj(ftpuser_config)

        db.session.add(ftpuser_config)
        db.session.commit()

        log_audit('CREATE', 'tb_ftpusers', ftpuser_config.id_ftpusers, f'Usuário FTP criado: {ftpuser_config.usuario}')
        flash('Usuário FTP criado com sucesso!', 'success')
        return redirect(url_for('list_ftpusers'))

    return render_template('notifications/ftpusers_form.html', form=form, title='Novo Usuário FTP')

@app.route('/notificacoes/ftpusers/<int:id>/editar', methods=['GET', 'POST'])
@login_required
def edit_ftpusers(id):
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_ftpusers'))

    ftpuser_config = FTPUsers.query.get_or_404(id)
    if ftpuser_config.is_deleted:
        abort(404)

    form = FTPUsersForm(obj=ftpuser_config)
    if form.validate_on_submit():
        form.populate_obj(ftpuser_config)
        db.session.commit()

        log_audit('UPDATE', 'tb_ftpusers', id, f'Usuário FTP editado: {ftpuser_config.usuario}')
        flash('Usuário FTP atualizado com sucesso!', 'success')

        # Check if coming from advanced search
        if request.referrer and 'busca-avancada' in request.referrer:
            return redirect(url_for('advanced_search'))
        return redirect(url_for('list_ftpusers'))

    return render_template('notifications/ftpusers_form.html', form=form, ftpuser_config=ftpuser_config, title='Editar Usuário FTP')

@app.route('/notificacoes/ftpusers/<int:id>/deletar', methods=['POST'])
@login_required
def delete_ftpusers(id):
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_ftpusers'))

    ftpuser_config = FTPUsers.query.get_or_404(id)
    if ftpuser_config.is_deleted:
        abort(404)

    # Salva dados para possível restauração
    import json
    config_data = {
        'usuario': ftpuser_config.usuario or '',
        'mf_unit': ftpuser_config.mf_unit or ''
    }

    ftpuser_config.is_deleted = True
    db.session.commit()

    log_audit('DELETE', 'tb_ftpusers', id, json.dumps(config_data))
    flash('Usuário FTP deletado com sucesso!', 'success')
    return redirect(url_for('list_ftpusers'))

@app.route('/notificacoes/ftpusers/<int:id>/view')
@login_required
def view_ftpusers_config(id):
    ftpuser_config = FTPUsers.query.get_or_404(id)
    if ftpuser_config.is_deleted:
        abort(404)

    config_data = {
        'id': ftpuser_config.id_ftpusers,
        'usuario': ftpuser_config.usuario or '',
        'mf_unit': ftpuser_config.mf_unit or '',
        'senha': '***' if ftpuser_config.senha else 'Não configurada'
    }

    return jsonify(config_data)

@app.route('/notificacoes/ftpusers/<int:id>')
@login_required
def view_ftpuser_page(id):
    ftpuser_config = FTPUsers.query.get_or_404(id)
    if ftpuser_config.is_deleted:
        abort(404)

    return render_template('notifications/ftpuser_view.html', config=ftpuser_config)

# Mail Groups routes
@app.route('/notificacoes/mailgroup')
@login_required
def list_mailgroup():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    search = request.args.get('search', '', type=str)

    query = MailGroup.query.filter(MailGroup.is_deleted == False)

    if search:
        search_pattern = f'%{search}%'
        query = query.filter(MailGroup.grupo.ilike(search_pattern))

    configs = query.order_by(MailGroup.grupo).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return render_template('notifications/mailgroup.html', configs=configs, search=search)

@app.route('/notificacoes/mailgroup/novo', methods=['GET', 'POST'])
@login_required
def create_mailgroup():
    if not current_user.is_advanced():
        flash('Acesso negado. Você precisa de permissões avançadas para acessar esta funcionalidade.', 'danger')
        return redirect(url_for('list_mailgroup'))

    form = MailGroupForm()
    if form.validate_on_submit():
        mailgroup_config = MailGroup()
        form.populate_obj(mailgroup_config)

        db.session.add(mailgroup_config)
        db.session.commit()

        log_audit('CREATE', 'tb_mailgroup', mailgroup_config.id_mailgroup, f'Grupo de Mail criado: {mailgroup_config.grupo}')
        flash('Grupo de Mail criado com sucesso!', 'success')
        return redirect(url_for('list_mailgroup'))

    return render_template('notifications/mailgroup_form.html', form=form, title='Novo Grupo de Mail')

@app.route('/notificacoes/mailgroup/<int:id>/editar', methods=['GET', 'POST'])
@login_required
def edit_mailgroup(id):
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_mailgroup'))

    mailgroup_config = MailGroup.query.get_or_404(id)
    if mailgroup_config.is_deleted:
        abort(404)

    form = MailGroupForm(obj=mailgroup_config)
    if form.validate_on_submit():
        form.populate_obj(mailgroup_config)
        db.session.commit()

        log_audit('UPDATE', 'tb_mailgroup', id, f'Grupo de Mail editado: {mailgroup_config.grupo}')
        flash('Grupo de Mail atualizado com sucesso!', 'success')

        # Check if coming from advanced search
        if request.referrer and 'busca-avancada' in request.referrer:
            return redirect(url_for('advanced_search'))
        return redirect(url_for('list_mailgroup'))

    return render_template('notifications/mailgroup_form.html', form=form, mailgroup_config=mailgroup_config, title='Editar Grupo de Mail')

@app.route('/notificacoes/mailgroup/<int:id>/deletar', methods=['POST'])
@login_required
def delete_mailgroup(id):
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_mailgroup'))

    mailgroup_config = MailGroup.query.get_or_404(id)
    if mailgroup_config.is_deleted:
        abort(404)

    # Salva dados para possível restauração
    import json
    config_data = {
        'grupo': mailgroup_config.grupo or '',
        'dst': mailgroup_config.dst or ''
    }

    mailgroup_config.is_deleted = True
    db.session.commit()

    log_audit('DELETE', 'tb_mailgroup', id, json.dumps(config_data))
    flash('Grupo de Mail deletado com sucesso!', 'success')
    return redirect(url_for('list_mailgroup'))

@app.route('/notificacoes/mailgroup/<int:id>/view')
@login_required
def view_mailgroup_config(id):
    mailgroup_config = MailGroup.query.get_or_404(id)
    if mailgroup_config.is_deleted:
        abort(404)

    dst_count = 0
    if mailgroup_config.dst:
        dst_count = len([line.strip() for line in mailgroup_config.dst.split('\n') if line.strip()])

    config_data = {
        'id': mailgroup_config.id_mailgroup,
        'grupo': mailgroup_config.grupo or '',
        'dst': mailgroup_config.dst or '',
        'dst_count': dst_count
    }

    return jsonify(config_data)

@app.route('/notificacoes/mailgroup/<int:id>')
@login_required
def view_mailgroup_page(id):
    mailgroup_config = MailGroup.query.get_or_404(id)
    if mailgroup_config.is_deleted:
        abort(404)

    return render_template('notifications/mailgroup_view.html', config=mailgroup_config)

# ROSCOE routes
@app.route('/notificacoes/roscoe')
@login_required
def list_roscoe():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    search = request.args.get('search', '', type=str)

    query = Roscoe.query.filter(Roscoe.is_deleted == False)

    if search:
        search_pattern = f'%{search}%'
        query = query.filter(Roscoe.chave.ilike(search_pattern))

    configs = query.order_by(Roscoe.chave).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return render_template('notifications/roscoe.html', configs=configs, search=search)

@app.route('/notificacoes/roscoe/novo', methods=['GET', 'POST'])
@login_required
def create_roscoe():
    if not current_user.is_advanced():
        flash('Acesso negado. Você precisa de permissões avançadas para acessar esta funcionalidade.', 'danger')
        return redirect(url_for('list_roscoe'))

    form = RoscoeForm()
    if form.validate_on_submit():
        roscoe_config = Roscoe()
        form.populate_obj(roscoe_config)

        db.session.add(roscoe_config)
        db.session.commit()

        log_audit('CREATE', 'tb_roscoe', roscoe_config.id_roscoe, f'Configuração ROSCOE criada: {roscoe_config.chave}')
        flash('Configuração ROSCOE criada com sucesso!', 'success')
        return redirect(url_for('list_roscoe'))

    return render_template('notifications/roscoe_form.html', form=form, title='Nova Configuração ROSCOE')

@app.route('/notificacoes/roscoe/<int:id>/editar', methods=['GET', 'POST'])
@login_required
def edit_roscoe(id):
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_roscoe'))

    roscoe_config = Roscoe.query.get_or_404(id)
    if roscoe_config.is_deleted:
        abort(404)

    form = RoscoeForm(obj=roscoe_config)
    if form.validate_on_submit():
        form.populate_obj(roscoe_config)
        db.session.commit()

        log_audit('UPDATE', 'tb_roscoe', id, f'Configuração ROSCOE editada: {roscoe_config.chave}')
        flash('Configuração ROSCOE atualizada com sucesso!', 'success')

        # Check if coming from advanced search
        if request.referrer and 'busca-avancada' in request.referrer:
            return redirect(url_for('advanced_search'))
        return redirect(url_for('list_roscoe'))

    return render_template('notifications/roscoe_form.html', form=form, roscoe_config=roscoe_config, title='Editar Configuração ROSCOE')

@app.route('/notificacoes/roscoe/<int:id>/deletar', methods=['POST'])
@login_required
def delete_roscoe(id):
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_roscoe'))

    roscoe_config = Roscoe.query.get_or_404(id)
    if roscoe_config.is_deleted:
        abort(404)

    # Salva dados para possível restauração
    import json
    config_data = {
        'chave': roscoe_config.chave or '',
        'dst': roscoe_config.dst or ''
    }

    roscoe_config.is_deleted = True
    db.session.commit()

    log_audit('DELETE', 'tb_roscoe', id, json.dumps(config_data))
    flash('Configuração ROSCOE deletada com sucesso!', 'success')
    return redirect(url_for('list_roscoe'))

@app.route('/notificacoes/roscoe/<int:id>/view')
@login_required
def view_roscoe_config(id):
    roscoe_config = Roscoe.query.get_or_404(id)
    if roscoe_config.is_deleted:
        abort(404)

    dst_count = 0
    if roscoe_config.dst:
        dst_count = len([line.strip() for line in roscoe_config.dst.split('\n') if line.strip()])

    config_data = {
        'id': roscoe_config.id_roscoe,
        'chave': roscoe_config.chave or '',
        'dst': roscoe_config.dst or '',
        'dst_count': dst_count
    }

    return jsonify(config_data)

@app.route('/notificacoes/roscoe/<int:id>')
@login_required
def view_roscoe_page(id):
    roscoe_config = Roscoe.query.get_or_404(id)
    if roscoe_config.is_deleted:
        abort(404)

    return render_template('notifications/roscoe_view.html', config=roscoe_config)

# SCP routes
@app.route('/protocolos/scp')
@login_required
def list_scp():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    search = request.args.get('search', '', type=str)

    # Join with Perfil and filter out orphaned records
    query = db.session.query(SCP, Perfil).join(Perfil).filter(
        SCP.is_deleted == False,
        Perfil.is_deleted == False,
        Perfil.scp == True
    )

    if search:
        search_pattern = f'%{search}%'
        query = query.filter(or_(
            Perfil.perfil.ilike(search_pattern),
            SCP.servidor.ilike(search_pattern),
            SCP.usuario.ilike(search_pattern)
        ))

    configs = query.order_by(Perfil.perfil).paginate(
        page=page, per_page=per_page, error_out=False
    )

    # Clean up orphaned SCP records (records that reference deleted profiles)
    try:
        orphaned_scp = db.session.query(SCP).outerjoin(Perfil).filter(
            SCP.is_deleted == False,
            or_(Perfil.id_perfil == None, Perfil.is_deleted == True, Perfil.scp == False)
        ).all()

        if orphaned_scp:
            for scp in orphaned_scp:
                scp.is_deleted = True
            db.session.commit()
            if len(orphaned_scp) > 0:
                flash(f'Foram removidas {len(orphaned_scp)} configurações SCP órfãs (perfis inexistentes).', 'info')
    except Exception as e:
        db.session.rollback()
        app.logger.warning(f"Erro ao limpar registros SCP órfãos: {str(e)}")

    # Buscar perfis com SCP habilitado para o dropdown
    perfis_scp = Perfil.query.filter_by(scp=True, is_deleted=False).order_by(Perfil.perfil).all()

    return render_template('protocols/scp.html', configs=configs, search=search, perfis_scp=perfis_scp)

@app.route('/protocolos/scp/novo', methods=['GET', 'POST'])
@login_required
def create_scp():
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_scp'))

    form = SCPForm()
    # Populate profile choices  
    perfis_scp = Perfil.query.filter_by(scp=True, is_deleted=False).order_by(Perfil.perfil).all()
    form.perfil_id.choices = [(p.id_perfil, p.perfil) for p in perfis_scp]

    # Validate if any profiles are available
    if not perfis_scp:
        flash('Não há perfis com SCP habilitado disponíveis. Crie ou habilite um perfil primeiro.', 'warning')
        return redirect(url_for('list_scp'))

    # Pré-selecionar perfil (recém-criado ou visualizado)
    preselect_profile_id = session.get('last_created_profile_id') or session.get('current_viewing_profile_id')
    if preselect_profile_id:
        # Verificar se o perfil ainda existe e tem SCP habilitado
        preselect_perfil = Perfil.query.filter_by(id_perfil=preselect_profile_id, scp=True, is_deleted=False).first()
        if preselect_perfil:
            form.perfil_id.data = preselect_profile_id
        # Remover o perfil da sessão após usar
        session.pop('last_created_profile_id', None)

    if form.validate_on_submit():
        try:
            # Apply trim to remove leading/trailing whitespace
            form = trim_form_data(form)

            # CRITICAL: Validate profile existence with explicit session refresh
            db.session.commit()  # Commit any pending transactions first
            perfil = Perfil.query.filter_by(id_perfil=form.perfil_id.data, is_deleted=False).first()

            if not perfil:
                flash('ERRO: Perfil selecionado não existe no banco de dados. Recarregue a página e selecione um perfil válido.', 'danger')
                # Force refresh of profile choices from database
                db.session.rollback()
                perfis_scp = Perfil.query.filter_by(scp=True, is_deleted=False).order_by(Perfil.perfil).all()
                form.perfil_id.choices = [(p.id_perfil, p.perfil) for p in perfis_scp]
                form.perfil_id.data = None  # Clear invalid selection
                return render_template('protocols/scp_form.html', form=form, title='Nova Configuração SCP')

            if not perfil.scp:
                flash('ERRO: Perfil selecionado não tem SCP habilitado. Selecione um perfil com SCP ativo.', 'danger')
                # Refresh profile choices to show only valid ones
                perfis_scp = Perfil.query.filter_by(scp=True, is_deleted=False).order_by(Perfil.perfil).all()
                form.perfil_id.choices = [(p.id_perfil, p.perfil) for p in perfis_scp]
                form.perfil_id.data = None  # Clear invalid selection
                return render_template('protocols/scp_form.html', form=form, title='Nova Configuração SCP')

            # Check if SCP configuration already exists for this profile
            existing_scp = SCP.query.filter_by(id_perfil=form.perfil_id.data, is_deleted=False).first()
            if existing_scp:
                flash(f'Já existe uma configuração SCP para o perfil "{perfil.perfil}". Edite a configuração existente.', 'warning')
                return redirect(url_for('edit_scp', id=existing_scp.id_scp))

            # Double-check that the profile still exists right before creating SCP
            check_perfil = Perfil.query.get(form.perfil_id.data)
            if not check_perfil or check_perfil.is_deleted:
                raise Exception("Perfil foi deletado durante o processo de criação")

            # Create SCP configuration with explicit profile validation
            scp_config = SCP()
            scp_config.id_perfil = perfil.id_perfil  # Use the validated profile ID

            # Set other fields from form
            for field in form:
                if field.name != 'perfil_id' and field.name != 'csrf_token' and hasattr(scp_config, field.name):
                    setattr(scp_config, field.name, field.data)

            # Test the foreign key constraint before final commit
            db.session.add(scp_config)
            db.session.flush()  # This validates constraints without committing
            db.session.commit()

            log_audit('CREATE', 'tb_scp', scp_config.id_scp, f'Configuração SCP criada para perfil: {perfil.perfil}')
            flash('Configuração SCP criada com sucesso!', 'success')
            return redirect(url_for('list_scp'))

        except Exception as e:
            db.session.rollback()
            error_msg = str(e)

            if any(constraint_error in error_msg.upper() for constraint_error in ['ORA-02291', 'PARENT KEY NOT FOUND', 'SYS_C007577', 'FOREIGN KEY']):
                flash('Erro de integridade: O perfil selecionado não existe no banco de dados. A página foi recarregada automaticamente. Selecione um perfil válido.', 'danger')
                app.logger.error(f"Foreign key constraint violation in SCP creation for profile {form.perfil_id.data}: {error_msg}")
            else:
                flash(f'Erro ao criar configuração SCP: {error_msg}', 'danger')
                app.logger.error(f"General error in SCP creation: {error_msg}")

            # Force refresh of profile choices from database
            perfis_scp = Perfil.query.filter_by(scp=True, is_deleted=False).order_by(Perfil.perfil).all()
            form.perfil_id.choices = [(p.id_perfil, p.perfil) for p in perfis_scp]
            form.perfil_id.data = None  # Clear the invalid selection
            return render_template('protocols/scp_form.html', form=form, title='Nova Configuração SCP')

    return render_template('protocols/scp_form.html', form=form, title='Nova Configuração SCP')

@app.route('/protocolos/scp/<int:id>/view')
@login_required
def view_scp_config(id):
    scp_config = SCP.query.get_or_404(id)
    if scp_config.is_deleted:
        abort(404)

    # Check if the associated profile still exists
    if not scp_config.perfil or scp_config.perfil.is_deleted:
        return jsonify({'error': 'Perfil associado não encontrado ou foi deletado'}), 404

    config_data = {
        'id': scp_config.id_scp,
        'perfil': scp_config.perfil.perfil,
        'servidor': scp_config.servidor or '',
        'porta': scp_config.porta or 22,
        'usuario': scp_config.usuario or '',
        'dir_local': scp_config.dir_local or '',
        'dir_remoto': scp_config.dir_remoto or '',
        'arquivo_local': scp_config.arquivo_local or '',
        'arquivo_remoto': scp_config.arquivo_remoto or '',
        'comando': scp_config.comando or '',
        'ssh': scp_config.ssh or '',
        'ok': scp_config.ok or '',
        'nok': scp_config.nok or '',
        'tel': scp_config.tel or '',
        'pri': scp_config.pri or '',
        'zip': scp_config.zip or False,
        'crlf': scp_config.crlf or False,
        'rel': scp_config.rel or False,
        'bin': scp_config.bin or False,
        'dmz': scp_config.dmz or False,
        'code': scp_config.code or False
    }
    return jsonify(config_data)

@app.route('/protocolos/scp/<int:id>/editar', methods=['GET', 'POST'])
@login_required
def edit_scp(id):
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_scp'))

    scp_config = SCP.query.get_or_404(id)
    if scp_config.is_deleted:
        abort(404)

    form = SCPForm(obj=scp_config)
    # Populate profile choices
    perfis_scp = Perfil.query.filter_by(scp=True, is_deleted=False).order_by(Perfil.perfil).all()
    form.perfil_id.choices = [(p.id_perfil, p.perfil) for p in perfis_scp]
    # Pre-select the current profile
    form.perfil_id.data = scp_config.id_perfil

    if form.validate_on_submit():
        try:
            # Apply trim to remove leading/trailing whitespace
            form = trim_form_data(form)

            # Validate if the new perfil exists and has SCP enabled (in case user changed it)
            perfil = Perfil.query.filter_by(id_perfil=form.perfil_id.data, is_deleted=False).first()
            if not perfil:
                flash('Erro: Perfil selecionado não existe ou foi deletado.', 'danger')
                # Refresh profile choices
                perfis_scp = Perfil.query.filter_by(scp=True, is_deleted=False).order_by(Perfil.perfil).all()
                form.perfil_id.choices = [(p.id_perfil, p.perfil) for p in perfis_scp]
                return render_template('protocols/scp_form.html', form=form, scp_config=scp_config, title='Editar Configuração SCP')

            if not perfil.scp:
                flash('Erro: Perfil selecionado não tem SCP habilitado.', 'danger')
                # Refresh profile choices
                perfis_scp = Perfil.query.filter_by(scp=True, is_deleted=False).order_by(Perfil.perfil).all()
                form.perfil_id.choices = [(p.id_perfil, p.perfil) for p in perfis_scp]
                return render_template('protocols/scp_form.html', form=form, scp_config=scp_config, title='Editar Configuração SCP')

            # Check if another SCP config exists for the new profile (if profile was changed)
            if form.perfil_id.data != scp_config.id_perfil:
                existing_scp = SCP.query.filter_by(id_perfil=form.perfil_id.data, is_deleted=False).first()
                if existing_scp:
                    flash(f'Já existe uma configuração SCP para o perfil "{perfil.perfil}". Cada perfil pode ter apenas uma configuração SCP.', 'warning')
                    # Reset to original profile
                    form.perfil_id.data = scp_config.id_perfil
                    return render_template('protocols/scp_form.html', form=form, scp_config=scp_config, title='Editar Configuração SCP')

            # Update fields
            scp_config.zip = form.zip.data if form.zip.data is not None else False
            scp_config.crlf = form.crlf.data if form.crlf.data is not None else False
            scp_config.rel = form.rel.data if form.rel.data is not None else False
            scp_config.bin = form.bin.data if form.bin.data is not None else False
            scp_config.dmz = form.dmz.data if form.dmz.data is not None else False
            scp_config.code = form.code.data if form.code.data is not None else False

            form.populate_obj(scp_config)

            # Restore boolean fields (in case populate_obj overwrote them)
            scp_config.zip = form.zip.data if form.zip.data is not None else False
            scp_config.crlf = form.crlf.data if form.crlf.data is not None else False
            scp_config.rel = form.rel.data if form.rel.data is not None else False
            scp_config.bin = form.bin.data if form.bin.data is not None else False
            scp_config.dmz = form.dmz.data if form.dmz.data is not None else False
            scp_config.code = form.code.data if form.code.data is not None else False

            db.session.commit()

            log_audit('UPDATE', 'tb_scp', id, f'Configuração SCP editada para perfil: {perfil.perfil}')
            flash('Configuração SCP atualizada com sucesso!', 'success')

            # Check if coming from advanced search
            if request.referrer and 'busca-avancada' in request.referrer:
                return redirect(url_for('advanced_search'))
            return redirect(url_for('list_scp'))

        except Exception as e:
            db.session.rollback()
            error_msg = str(e)
            if 'ORA-02291' in error_msg or 'parent key not found' in error_msg:
                flash('Erro de integridade: O perfil selecionado não existe no banco de dados.', 'danger')
            else:
                flash(f'Erro ao atualizar configuração SCP: {error_msg}', 'danger')

            # Refresh profile choices after error
            perfis_scp = Perfil.query.filter_by(scp=True, is_deleted=False).order_by(Perfil.perfil).all()
            form.perfil_id.choices = [(p.id_perfil, p.perfil) for p in perfis_scp]
            return render_template('protocols/scp_form.html', form=form, scp_config=scp_config, title='Editar Configuração SCP')

    return render_template('protocols/scp_form.html', form=form, scp_config=scp_config, title='Editar Configuração SCP')

@app.route('/protocolos/scp/<int:id>/deletar', methods=['POST'])
@login_required
def delete_scp(id):
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_scp'))

    scp_config = SCP.query.get_or_404(id)
    if scp_config.is_deleted:
        abort(404)

    try:
        # Salva dados completos para restauração
        import json
        scp_data = {
            'perfil_id': scp_config.id_perfil,
            'servidor': scp_config.servidor,
            'porta': scp_config.porta,
            'usuario': scp_config.usuario,
            'senha': scp_config.senha,
            'dir_local': scp_config.dir_local,
            'dir_remoto': scp_config.dir_remoto,
            'arquivo_local': scp_config.arquivo_local,
            'arquivo_remoto': scp_config.arquivo_remoto,
            'comando': scp_config.comando,
            'ssh': scp_config.ssh,
            'ok': scp_config.ok,
            'nok': scp_config.nok,
            'tel': scp_config.tel,
            'pri': scp_config.pri,
            'zip': scp_config.zip,
            'crlf': scp_config.crlf,
            'rel': scp_config.rel,
            'bin': scp_config.bin,
            'dmz': scp_config.dmz,
            'code': scp_config.code
        }

        # Get profile name for logging (before deletion)
        perfil_nome = scp_config.perfil.perfil if scp_config.perfil else f"ID {scp_config.id_perfil}"

        scp_config.is_deleted = True
        db.session.commit()

        log_audit('DELETE', 'tb_scp', id, json.dumps(scp_data, ensure_ascii=False))
        flash('Configuração SCP deletada com sucesso!', 'success')

    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao deletar configuração SCP: {str(e)}', 'danger')

    return redirect(url_for('list_scp'))

# HTTP routes
@app.route('/protocolos/http')
@login_required
def list_http():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    search = request.args.get('search', '', type=str)

    query = db.session.query(HTTP, Perfil).join(Perfil).filter(HTTP.is_deleted == False)

    if search:
        search_pattern = f'%{search}%'
        query = query.filter(or_(
            Perfil.perfil.ilike(search_pattern),
            HTTP.dns.ilike(search_pattern),
            HTTP.uri.ilike(search_pattern)
        ))

    configs = query.order_by(Perfil.perfil).paginate(
        page=page, per_page=per_page, error_out=False
    )

    # Buscar perfis com HTTP habilitado para o dropdown
    perfis_http = Perfil.query.filter_by(http=True, is_deleted=False).all()

    return render_template('protocols/http.html', configs=configs, search=search, perfis_http=perfis_http)

@app.route('/protocolos/http/novo', methods=['GET', 'POST'])
@login_required
def create_http():
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_http'))

    form = HTTPForm()
    # Populate profile choices
    perfis_http = Perfil.query.filter_by(http=True, is_deleted=False).all()
    form.perfil_id.choices = [(p.id_perfil, p.perfil) for p in perfis_http]

    # Pré-selecionar perfil (recém-criado ou visualizado)
    preselect_profile_id = session.get('last_created_profile_id') or session.get('current_viewing_profile_id')
    if preselect_profile_id and any(p.id_perfil == preselect_profile_id for p in perfis_http):
        form.perfil_id.data = preselect_profile_id
        # Remover apenas o perfil recém-criado da sessão após usar
        session.pop('last_created_profile_id', None)

    if form.validate_on_submit():
        # Apply trim to remove leading/trailing whitespace
        form = trim_form_data(form)
        perfil = Perfil.query.get_or_404(form.perfil_id.data)
        if not perfil.http or perfil.is_deleted:
            flash('Perfil não permite configuração HTTP.', 'danger')
            return redirect(url_for('list_http'))

        http_config = HTTP(id_perfil=form.perfil_id.data)
        form.populate_obj(http_config)

        db.session.add(http_config)
        db.session.commit()

        log_audit('CREATE', 'tb_http', http_config.id_http, f'Configuração HTTP criada para perfil: {perfil.perfil}')
        flash('Configuração HTTP criada com sucesso!', 'success')
        return redirect(url_for('list_http'))

    return render_template('protocols/http_form.html', form=form, title='Nova Configuração HTTP')

@app.route('/protocolos/http/<int:id>/view')
@login_required
def view_http_config(id):
    http_config = HTTP.query.get_or_404(id)
    if http_config.is_deleted:
        abort(404)

    config_data = {
        'id': http_config.id_http,
        'perfil': http_config.perfil.perfil,
        'dns': http_config.dns or '',
        'porta': http_config.porta or '',
        'uri': http_config.uri or '',
        'metodo': http_config.metodo or '',
        'prms': http_config.prms or '',
        'hash': http_config.hash or '',
        'tipo_arq': http_config.tipo_arq or '',
        'cert': http_config.cert or '',
        'json': http_config.json or False,
        'usuario': http_config.usuario or '',
        'dmz': http_config.dmz or False
    }
    return jsonify(config_data)

@app.route('/protocolos/http/<int:id>/editar', methods=['GET', 'POST'])
@login_required
def edit_http(id):
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_http'))

    http_config = HTTP.query.get_or_404(id)
    if http_config.is_deleted:
        abort(404)

    form = HTTPForm(obj=http_config)
    # Populate profile choices
    perfis_http = Perfil.query.filter_by(http=True, is_deleted=False).all()
    form.perfil_id.choices = [(p.id_perfil, p.perfil) for p in perfis_http]
    # Pre-select the current profile
    form.perfil_id.data = http_config.id_perfil
    if form.validate_on_submit():
        # Apply trim to remove leading/trailing whitespace
        form = trim_form_data(form)
        # Manually update boolean fields
        http_config.dmz = form.dmz.data if form.dmz.data is not None else False

        form.populate_obj(http_config)

        # Restore boolean fields
        http_config.dmz = form.dmz.data if form.dmz.data is not None else False

        db.session.commit()

        log_audit('UPDATE', 'tb_http', id, f'Configuração HTTP editada para perfil: {http_config.perfil.perfil}')
        flash('Configuração HTTP atualizada com sucesso!', 'success')
        return redirect(url_for('list_http'))

    return render_template('protocols/http_form.html', form=form, http_config=http_config, title='Editar Configuração HTTP')

@app.route('/protocolos/http/<int:id>/deletar', methods=['POST'])
@login_required
def delete_http(id):
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_http'))

    http_config = HTTP.query.get_or_404(id)
    if http_config.is_deleted:
        abort(404)

    # Salva dados completos para restauração
    import json
    http_data = {
        'perfil_id': http_config.id_perfil,
        'dns': http_config.dns,
        'porta': http_config.porta,
        'uri': http_config.uri,
        'metodo': http_config.metodo,
        'prms': http_config.prms,
        'hash': http_config.hash,
        'tipo_arq': http_config.tipo_arq,
        'cert': http_config.cert,
        'json': http_config.json,
        'usuario': http_config.usuario,
        'dmz': http_config.dmz
    }

    http_config.is_deleted = True
    db.session.commit()

    log_audit('DELETE', 'tb_http', id, json.dumps(http_data, ensure_ascii=False))
    flash('Configuração HTTP deletada com sucesso!', 'success')
    return redirect(url_for('list_http'))

# S3 routes
@app.route('/protocolos/s3')
@login_required
def list_s3():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    search = request.args.get('search', '', type=str)

    query = db.session.query(S3, Perfil).join(Perfil).filter(S3.is_deleted == False)

    if search:
        search_pattern = f'%{search}%'
        query = query.filter(or_(
            Perfil.perfil.ilike(search_pattern),
            S3.bucketname.ilike(search_pattern),
            S3.endpointurl.ilike(search_pattern)
        ))

    configs = query.order_by(Perfil.perfil).paginate(
        page=page, per_page=per_page, error_out=False
    )

    # Buscar perfis com S3 habilitado para o dropdown
    perfis_s3 = Perfil.query.filter_by(s3=True, is_deleted=False).all()

    return render_template('protocols/s3.html', configs=configs, search=search, perfis_s3=perfis_s3)

@app.route('/protocolos/s3/novo', methods=['GET', 'POST'])
@login_required
def create_s3():
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_s3'))

    form = S3Form()
    # Populate profile choices
    perfis_s3 = Perfil.query.filter_by(s3=True, is_deleted=False).all()
    form.perfil_id.choices = [(p.id_perfil, p.perfil) for p in perfis_s3]

    # Pré-selecionar perfil (recém-criado ou visualizado)
    preselect_profile_id = session.get('last_created_profile_id') or session.get('current_viewing_profile_id')
    if preselect_profile_id and any(p.id_perfil == preselect_profile_id for p in perfis_s3):
        form.perfil_id.data = preselect_profile_id
        # Remover apenas o perfil recém-criado da sessão após usar
        session.pop('last_created_profile_id', None)

    if form.validate_on_submit():
        # Apply trim to remove leading/trailing whitespace
        form = trim_form_data(form)
        perfil = Perfil.query.get_or_404(form.perfil_id.data)
        if not perfil.s3 or perfil.is_deleted:
            flash('Perfil não permite configuração S3.', 'danger')
            return redirect(url_for('list_s3'))

        s3_config = S3(id_perfil=form.perfil_id.data)
        form.populate_obj(s3_config)

        db.session.add(s3_config)
        db.session.commit()

        log_audit('CREATE', 'tb_s3', s3_config.id_s3, f'Configuração S3 criada para perfil: {perfil.perfil}')
        flash('Configuração S3 criada com sucesso!', 'success')
        return redirect(url_for('list_s3'))

    return render_template('protocols/s3_form.html', form=form, title='Nova Configuração S3')

@app.route('/protocolos/s3/<int:id>/view')
@login_required
def view_s3_config(id):
    s3_config = S3.query.get_or_404(id)
    if s3_config.is_deleted:
        abort(404)

    config_data = {
        'id': s3_config.id_s3,
        'perfil': s3_config.perfil.perfil,
        'bucketname': s3_config.bucketname or '',
        'region': s3_config.region or '',
        'accesskey': s3_config.accesskey or '',
        'secretkey': '***' if s3_config.secretkey else '',
        'endpointurl': s3_config.endpointurl or '',
        'action': s3_config.action or '',
        'dmz': s3_config.dmz or False
    }
    return jsonify(config_data)

@app.route('/protocolos/s3/<int:id>/editar', methods=['GET', 'POST'])
@login_required
def edit_s3(id):
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_s3'))

    s3_config = S3.query.get_or_404(id)
    if s3_config.is_deleted:
        abort(404)

    form = S3Form(obj=s3_config)
    # Populate profile choices
    perfis_s3 = Perfil.query.filter_by(s3=True, is_deleted=False).all()
    form.perfil_id.choices = [(p.id_perfil, p.perfil) for p in perfis_s3]
    # Pre-select the current profile
    form.perfil_id.data = s3_config.id_perfil
    if form.validate_on_submit():
        # Apply trim to remove leading/trailing whitespace
        form = trim_form_data(form)
        form.populate_obj(s3_config)
        db.session.commit()

        log_audit('UPDATE', 'tb_s3', id, f'Configuração S3 editada para perfil: {s3_config.perfil.perfil}')
        flash('Configuração S3 atualizada com sucesso!', 'success')
        return redirect(url_for('list_s3'))

    return render_template('protocols/s3_form.html', form=form, s3_config=s3_config, title='Editar Configuração S3')

@app.route('/protocolos/s3/<int:id>/deletar', methods=['POST'])
@login_required
def delete_s3(id):
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_s3'))

    s3_config = S3.query.get_or_404(id)
    if s3_config.is_deleted:
        abort(404)

    # Salva dados completos para restauração
    import json
    s3_data = {
        'perfil_id': s3_config.id_perfil,
        'endpointurl': s3_config.endpointurl,
        'endpointport': s3_config.endpointport,
        'bucketname': s3_config.bucketname,
        'action': s3_config.action,
        'accesskey': s3_config.accesskey,
        'secretkey': s3_config.secretkey,
        'foldername': s3_config.foldername,
        'filename': s3_config.filename,
        'localfilename': s3_config.localfilename,
        'header': s3_config.header,
        'acl': s3_config.acl,
        'tag': s3_config.tag,
        'ecs': s3_config.ecs,
        'region': s3_config.region,
        'dmz': s3_config.dmz
    }

    s3_config.is_deleted = True
    db.session.commit()

    log_audit('DELETE', 'tb_s3', id, json.dumps(s3_data, ensure_ascii=False))
    flash('Configuração S3 deletada com sucesso!', 'success')
    return redirect(url_for('list_s3'))

# Connect:Direct routes
@app.route('/protocolos/cd')
@login_required
def list_cd():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    search = request.args.get('search', '', type=str)

    query = db.session.query(CD, Perfil).join(Perfil).filter(CD.is_deleted == False)

    if search:
        search_pattern = f'%{search}%'
        query = query.filter(or_(
            Perfil.perfil.ilike(search_pattern),
            CD.node.ilike(search_pattern),
            CD.tit.ilike(search_pattern)
        ))

    configs = query.order_by(Perfil.perfil).paginate(
        page=page, per_page=per_page, error_out=False
    )

    # Buscar perfis com Connect:Direct habilitado para o dropdown
    perfis_cd = Perfil.query.filter_by(cd=True, is_deleted=False).all()

    return render_template('protocols/cd.html', configs=configs, search=search, perfis_cd=perfis_cd)

@app.route('/protocolos/cd/novo', methods=['GET', 'POST'])
@login_required
def create_cd():
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_cd'))

    form = CDForm()
    # Populate profile choices
    perfis_cd = Perfil.query.filter_by(cd=True, is_deleted=False).all()
    form.perfil_id.choices = [(p.id_perfil, p.perfil) for p in perfis_cd]

    # Pré-selecionar perfil (recém-criado ou visualizado)
    preselect_profile_id = session.get('last_created_profile_id') or session.get('current_viewing_profile_id')
    if preselect_profile_id and any(p.id_perfil == preselect_profile_id for p in perfis_cd):
        form.perfil_id.data = preselect_profile_id
        # Remover apenas o perfil recém-criado da sessão após usar
        session.pop('last_created_profile_id', None)

    if form.validate_on_submit():
        # Apply trim to remove leading/trailing whitespace
        form = trim_form_data(form)
        perfil = Perfil.query.get_or_404(form.perfil_id.data)
        if not perfil.cd or perfil.is_deleted:
            flash('Perfil não permite configuração Connect:Direct.', 'danger')
            return redirect(url_for('list_cd'))

        cd_config = CD(id_perfil=form.perfil_id.data)
        form.populate_obj(cd_config)

        db.session.add(cd_config)
        db.session.commit()

        log_audit('CREATE', 'tb_cd', cd_config.id_cd, f'Configuração Connect:Direct criada para perfil: {perfil.perfil}')
        flash('Configuração Connect:Direct criada com sucesso!', 'success')
        return redirect(url_for('list_cd'))

    return render_template('protocols/cd_form.html', form=form, title='Nova Configuração Connect:Direct')

@app.route('/protocolos/cd/<int:id>/view')
@login_required
def view_cd_config(id):
    cd_config = CD.query.get_or_404(id)
    if cd_config.is_deleted:
        abort(404)

    config_data = {
        'id': cd_config.id_cd,
        'perfil': cd_config.perfil.perfil,
        'tit': cd_config.tit or '',
        'node': cd_config.node or '',
        'job': cd_config.job or '',
        'tsk': cd_config.tsk or '',
        'dmz': cd_config.dmz or False
    }
    return jsonify(config_data)

@app.route('/protocolos/cd/<int:id>/editar', methods=['GET', 'POST'])
@login_required
def edit_cd(id):
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_cd'))

    cd_config = CD.query.get_or_404(id)
    if cd_config.is_deleted:
        abort(404)

    form = CDForm(obj=cd_config)
    # Populate profile choices
    perfis_cd = Perfil.query.filter_by(cd=True, is_deleted=False).all()
    form.perfil_id.choices = [(p.id_perfil, p.perfil) for p in perfis_cd]
    # Pre-select the current profile
    form.perfil_id.data = cd_config.id_perfil
    if form.validate_on_submit():
        # Apply trim to remove leading/trailing whitespace
        form = trim_form_data(form)
        form.populate_obj(cd_config)
        db.session.commit()

        log_audit('UPDATE', 'tb_cd', id, f'Configuração Connect:Direct editada para perfil: {cd_config.perfil.perfil}')
        flash('Configuração Connect:Direct atualizada com sucesso!', 'success')
        return redirect(url_for('list_cd'))

    return render_template('protocols/cd_form.html', form=form, cd_config=cd_config, title='Editar Configuração Connect:Direct')

@app.route('/protocolos/cd/<int:id>/deletar', methods=['POST'])
@login_required
def delete_cd(id):
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_cd'))

    cd_config = CD.query.get_or_404(id)
    if cd_config.is_deleted:
        abort(404)

    # Salva dados completos para restauração
    import json
    cd_data = {
        'perfil_id': cd_config.id_perfil,
        'node': cd_config.node,
        'tit': cd_config.tit,
        'aut': cd_config.aut,
        'dhd': cd_config.dhd,
        'dst': cd_config.dst,
        'dsn': cd_config.dsn,
        'dcb': cd_config.dcb,
        'codbanco': cd_config.codbanco,
        'tsk': cd_config.tsk,
        'job': cd_config.job,
        'spc': cd_config.spc,
        'dmz': cd_config.dmz,
        'disp': cd_config.disp,
        'sysopts': cd_config.sysopts,
        'opts': cd_config.opts
    }

    cd_config.is_deleted = True
    db.session.commit()

    log_audit('DELETE', 'tb_connect_direct', id, json.dumps(cd_data, ensure_ascii=False))
    flash('Configuração Connect:Direct deletada com sucesso!', 'success')
    return redirect(url_for('list_cd'))

# JASPPION routes
@app.route('/protocolos/jasppion')
@login_required
def list_jasppion():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    search = request.args.get('search', '', type=str)

    query = db.session.query(Jasppion, Perfil).join(Perfil).filter(Jasppion.is_deleted == False)

    if search:
        search_pattern = f'%{search}%'
        query = query.filter(or_(
            Perfil.perfil.ilike(search_pattern),
            Jasppion.servidor.ilike(search_pattern),
            Jasppion.programa.ilike(search_pattern)
        ))

    configs = query.order_by(Perfil.perfil).paginate(
        page=page, per_page=per_page, error_out=False
    )

    # Buscar perfis com JASPPION habilitado para o dropdown
    perfis_jasppion = Perfil.query.filter_by(jasppion=True, is_deleted=False).all()

    return render_template('protocols/jasppion.html', configs=configs, search=search, perfis_jasppion=perfis_jasppion)

# MQ routes
@app.route('/protocolos/mq')
@login_required
def list_mq():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    search = request.args.get('search', '', type=str)

    query = db.session.query(MQ, Perfil).join(Perfil).filter(MQ.is_deleted == False)

    if search:
        search_pattern = f'%{search}%'
        query = query.filter(or_(
            Perfil.perfil.ilike(search_pattern),
            MQ.hostname.ilike(search_pattern),
            MQ.userid.ilike(search_pattern)
        ))

    configs = query.order_by(Perfil.perfil).paginate(
        page=page, per_page=per_page, error_out=False
    )

    # Buscar perfis com MQ habilitado para o dropdown
    perfis_mq = Perfil.query.filter_by(mq=True, is_deleted=False).all()

    return render_template('protocols/mq.html', configs=configs, search=search, perfis_mq=perfis_mq)

@app.route('/protocolos/mq/novo', methods=['GET', 'POST'])
@login_required
def create_mq():
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_mq'))

    form = MQForm()
    # Populate profile choices
    perfis_mq = Perfil.query.filter_by(mq=True, is_deleted=False).all()
    form.perfil_id.choices = [(p.id_perfil, p.perfil) for p in perfis_mq]

    # Pré-selecionar perfil (recém-criado ou visualizado)
    preselect_profile_id = session.get('last_created_profile_id') or session.get('current_viewing_profile_id')
    if preselect_profile_id and any(p.id_perfil == preselect_profile_id for p in perfis_mq):
        form.perfil_id.data = preselect_profile_id
        # Remover apenas o perfil recém-criado da sessão após usar
        session.pop('last_created_profile_id', None)

    if form.validate_on_submit():
        # Apply trim to remove leading/trailing whitespace
        form = trim_form_data(form)
        perfil = Perfil.query.get_or_404(form.perfil_id.data)
        if not perfil.mq or perfil.is_deleted:
            flash('Perfil não permite configuração MQ.', 'danger')
            return redirect(url_for('list_mq'))

        mq_config = MQ(id_perfil=form.perfil_id.data)
        form.populate_obj(mq_config)
        # Ensure port field is properly mapped
        mq_config.port = form.port.data

        db.session.add(mq_config)
        db.session.commit()

        log_audit('CREATE', 'tb_mq', mq_config.id_mq, f'Configuração MQ criada para perfil: {perfil.perfil}')
        flash('Configuração MQ criada com sucesso!', 'success')
        return redirect(url_for('list_mq'))

    return render_template('protocols/mq_form.html', form=form, title='Nova Configuração MQ')

@app.route('/protocolos/mq/<int:id>/view')
@login_required
def view_mq_config(id):
    try:
        app.logger.info(f'Tentando visualizar configuração MQ ID: {id} pelo usuário {current_user.username}')

        mq_config = MQ.query.get(id)

        if not mq_config:
            app.logger.warning(f'Configuração MQ com ID {id} não encontrada')
            return jsonify({'error': 'Configuração MQ não encontrada'}), 404

        if mq_config.is_deleted:
            app.logger.warning(f'Configuração MQ com ID {id} foi deletada')
            return jsonify({'error': 'Configuração MQ foi deletada'}), 404

        # Check if the associated profile still exists
        if not mq_config.perfil or mq_config.perfil.is_deleted:
            app.logger.warning(f'Perfil associado à configuração MQ {id} não encontrado ou deletado')
            return jsonify({'error': 'Perfil associado não encontrado ou foi deletado'}), 404

        # Helper function to safely handle None values
        def safe_value(value, default=''):
            return value if value is not None else default

        config_data = {
            'id': mq_config.id_mq,
            'perfil': mq_config.perfil.perfil,
            'hostname': safe_value(mq_config.hostname),
            'port': mq_config.port or 1414,
            'channel': safe_value(mq_config.channel),
            'userid': safe_value(mq_config.userid),
            'qmgr': safe_value(mq_config.qmgr),
            'qname': safe_value(mq_config.qname),
            'action': safe_value(mq_config.action),
            'gettype': safe_value(mq_config.gettype),
            'msgtype': safe_value(mq_config.msgtype),
            'msgid': safe_value(mq_config.msgid),
            'ccsid': safe_value(mq_config.ccsid),
            'ttl': safe_value(mq_config.ttl),
            'ssl': bool(mq_config.ssl),
            'tls': safe_value(mq_config.tls),
            'cert': safe_value(mq_config.cert),
            'mail': bool(mq_config.mail),
            'mailmsg': safe_value(mq_config.mailmsg),
            'mailass': safe_value(mq_config.mailass),
            'maildest': safe_value(mq_config.maildest),
            'mailanexo': bool(mq_config.mailanexo)
        }

        app.logger.info(f'MQ config view successful for ID {id}')
        return jsonify(config_data)

    except Exception as e:
        app.logger.error(f'Erro ao visualizar configuração MQ {id}: {str(e)}', exc_info=True)
        return jsonify({'error': f'Erro interno do servidor: {str(e)}'}), 500

@app.route('/protocolos/mq/<int:id>/editar', methods=['GET', 'POST'])
@login_required
def edit_mq(id):
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_mq'))

    mq_config = MQ.query.get_or_404(id)
    if mq_config.is_deleted:
        abort(404)

    form = MQForm(obj=mq_config)
    # Populate profile choices
    perfis_mq = Perfil.query.filter_by(mq=True, is_deleted=False).all()
    form.perfil_id.choices = [(p.id_perfil, p.perfil) for p in perfis_mq]
    # Pre-select the current profile
    form.perfil_id.data = mq_config.id_perfil

    if form.validate_on_submit():
        # Apply trim to remove leading/trailing whitespace
        form = trim_form_data(form)
        # Manually update boolean fields
        mq_config.ssl = form.ssl.data if form.ssl.data is not None else False
        mq_config.mail = form.mail.data if form.mail.data is not None else False
        mq_config.mailanexo = form.mailanexo.data if form.mailanexo.data is not None else False

        form.populate_obj(mq_config)
        # Ensure port field is properly mapped
        mq_config.port = form.port.data

        # Restore boolean fields
        mq_config.ssl = form.ssl.data if form.ssl.data is not None else False
        mq_config.mail = form.mail.data if form.mail.data is not None else False
        mq_config.mailanexo = form.mailanexo.data if form.mailanexo.data is not None else False

        db.session.commit()

        log_audit('UPDATE', 'tb_mq', id, f'Configuração MQ editada para perfil: {mq_config.perfil.perfil}')
        flash('Configuração MQ atualizada com sucesso!', 'success')

        # Check if coming from advanced search
        if request.referrer and 'busca-avancada' in request.referrer:
            return redirect(url_for('advanced_search'))
        return redirect(url_for('list_mq'))

    return render_template('protocols/mq_form.html', form=form, mq_config=mq_config, title='Editar Configuração MQ')

@app.route('/protocolos/mq/<int:id>/deletar', methods=['POST'])
@login_required
def delete_mq(id):
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_mq'))

    mq_config = MQ.query.get_or_404(id)
    if mq_config.is_deleted:
        abort(404)

    # Salva dados completos para restauração
    import json
    mq_data = {
        'perfil_id': mq_config.id_perfil,
        'hostname': mq_config.hostname,
        'port': mq_config.port,
        'channel': mq_config.channel,
        'userid': mq_config.userid,
        'passwd': mq_config.passwd,
        'qmgr': mq_config.qmgr,
        'qname': mq_config.qname,
        'action': mq_config.action,
        'gettype': mq_config.gettype,
        'msgtype': mq_config.msgtype,
        'msgid': mq_config.msgid,
        'ccsid': mq_config.ccsid,
        'ttl': mq_config.ttl,
        'ssl': mq_config.ssl,
        'tls': mq_config.tls,
        'cert': mq_config.cert,
        'mail': mq_config.mail,
        'mailmsg': mq_config.mailmsg,
        'mailass': mq_config.mailass,
        'maildest': mq_config.maildest,
        'mailanexo': mq_config.mailanexo
    }

    mq_config.is_deleted = True
    db.session.commit()

    log_audit('DELETE', 'tb_mq', id, json.dumps(mq_data, ensure_ascii=False))
    flash('Configuração MQ deletada com sucesso!', 'success')
    return redirect(url_for('list_mq'))

@app.route('/protocolos/jasppion/novo', methods=['GET', 'POST'])
@login_required
def create_jasppion():
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_jasppion'))

    form = JasppionForm()
    # Populate profile choices
    perfis_jasppion = Perfil.query.filter_by(jasppion=True, is_deleted=False).all()
    form.perfil_id.choices = [(p.id_perfil, p.perfil) for p in perfis_jasppion]

    # Pré-selecionar perfil (recém-criado ou visualizado)
    preselect_profile_id = session.get('last_created_profile_id') or session.get('current_viewing_profile_id')
    if preselect_profile_id and any(p.id_perfil == preselect_profile_id for p in perfis_jasppion):
        form.perfil_id.data = preselect_profile_id
        # Remover apenas o perfil recém-criado da sessão após usar
        session.pop('last_created_profile_id', None)

    if form.validate_on_submit():
        # Apply trim to remove leading/trailing whitespace
        form = trim_form_data(form)
        perfil = Perfil.query.get_or_404(form.perfil_id.data)
        if not perfil.jasppion or perfil.is_deleted:
            flash('Perfil não permite configuração JASPPION.', 'danger')
            return redirect(url_for('list_jasppion'))

        jasppion_config = Jasppion(id_perfil=form.perfil_id.data)
        form.populate_obj(jasppion_config)

        db.session.add(jasppion_config)
        db.session.commit()

        log_audit('CREATE', 'tb_jasppion', jasppion_config.id_jasppion, f'Configuração JASPPION criada para perfil: {perfil.perfil}')
        flash('Configuração JASPPION criada com sucesso!', 'success')
        return redirect(url_for('list_jasppion'))

    return render_template('protocols/jasppion_form.html', form=form, title='Nova Configuração JASPPION')

@app.route('/protocolos/jasppion/<int:id>/view')
@login_required
def view_jasppion_config(id):
    jasppion_config = Jasppion.query.get_or_404(id)
    if jasppion_config.is_deleted:
        abort(404)

    config_data = {
        'id': jasppion_config.id_jasppion,
        'perfil': jasppion_config.perfil.perfil,
        'servidor': jasppion_config.servidor or '',
        'porta': jasppion_config.porta or '',
        'uri': jasppion_config.uri or '',
        'programa': jasppion_config.programa or '',
        'app': jasppion_config.app or '',
        'logon': jasppion_config.logon or '',
        'roscoe': jasppion_config.roscoe or False,
        'rcode': jasppion_config.rcode or '',
        'delimitador': jasppion_config.delimitador or '',
        'mail': jasppion_config.mail or False,
        'mailass': jasppion_config.mailass or '',
        'maildest': jasppion_config.maildest or '',
        'mailmsg': jasppion_config.mailmsg or '',
        'mailanexo': jasppion_config.mailanexo or False
    }
    return jsonify(config_data)

@app.route('/protocolos/jasppion/<int:id>/editar', methods=['GET', 'POST'])
@login_required
def edit_jasppion(id):
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_jasppion'))

    jasppion_config = Jasppion.query.get_or_404(id)
    if jasppion_config.is_deleted:
        abort(404)

    form = JasppionForm(obj=jasppion_config)
    # Populate profile choices
    perfis_jasppion = Perfil.query.filter_by(jasppion=True, is_deleted=False).all()
    form.perfil_id.choices = [(p.id_perfil, p.perfil) for p in perfis_jasppion]
    # Pre-select the current profile
    form.perfil_id.data = jasppion_config.id_perfil
    if form.validate_on_submit():
        # Apply trim to remove leading/trailing whitespace
        form = trim_form_data(form)
        form.populate_obj(jasppion_config)
        db.session.commit()

        log_audit('UPDATE', 'tb_jasppion', id, f'Configuração JASPPION editada para perfil: {jasppion_config.perfil.perfil}')
        flash('Configuração JASPPION atualizada com sucesso!', 'success')
        return redirect(url_for('list_jasppion'))

    return render_template('protocols/jasppion_form.html', form=form, jasppion_config=jasppion_config, title='Editar Configuração JASPPION')

@app.route('/protocolos/jasppion/<int:id>/deletar', methods=['POST'])
@login_required
def delete_jasppion(id):
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_jasppion'))

    jasppion_config = Jasppion.query.get_or_404(id)
    if jasppion_config.is_deleted:
        abort(404)

    # Salva dados completos para restauração
    import json
    jasppion_data = {
        'perfil_id': jasppion_config.id_perfil,
        'servidor': jasppion_config.servidor,
        'porta': jasppion_config.porta,
        'uri': jasppion_config.uri,
        'app': jasppion_config.app,
        'fsadabas': jasppion_config.fsadabas,
        'logon': jasppion_config.logon,
        'programa': jasppion_config.programa,
        'roscoe': jasppion_config.roscoe,
        'rcode': jasppion_config.rcode,
        'delimitador': jasppion_config.delimitador
    }

    jasppion_config.is_deleted = True
    db.session.commit()

    log_audit('DELETE', 'tb_jasppion', id, json.dumps(jasppion_data, ensure_ascii=False))
    flash('Configuração JASPPION deletada com sucesso!', 'success')
    return redirect(url_for('list_jasppion'))

# HeaderTrailer routes
@app.route('/funcionalidades/headertrailer')
@login_required
def list_headertrailer():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    search = request.args.get('search', '', type=str)

    query = db.session.query(HeaderTrailer, Perfil).join(Perfil).filter(HeaderTrailer.is_deleted == False)

    if search:
        search_pattern = f'%{search}%'
        query = query.filter(or_(
            Perfil.perfil.ilike(search_pattern),
            HeaderTrailer.htr0_p1.ilike(search_pattern),
            HeaderTrailer.htr3.ilike(search_pattern)
        ))

    configs = query.order_by(Perfil.perfil).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return render_template('functionalities/header_trailer.html', configs=configs, search=search)

@app.route('/funcionalidades/headertrailer/novo', methods=['GET', 'POST'])
@login_required
def create_headertrailer():
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_headertrailer'))

    form = HeaderTrailerForm()
    # Populate choices for perfil_id field
    perfis_ht = Perfil.query.filter_by(header_trailer=True, is_deleted=False).all()
    form.perfil_id.choices = [(p.id_perfil, p.perfil) for p in perfis_ht]

    # Pré-selecionar perfil (recém-criado ou visualizado)
    preselect_profile_id = session.get('last_created_profile_id') or session.get('current_viewing_profile_id')
    if preselect_profile_id and any(p.id_perfil == preselect_profile_id for p in perfis_ht):
        form.perfil_id.data = preselect_profile_id
        # Remover apenas o perfil recém-criado da sessão após usar
        session.pop('last_created_profile_id', None)

    if form.validate_on_submit():
        perfil = Perfil.query.get(form.perfil_id.data)
        if not perfil or not perfil.header_trailer or perfil.is_deleted:
            flash('Perfil não permite configuração HeaderTrailer.', 'danger')
            return redirect(url_for('list_headertrailer'))

        ht_config = HeaderTrailer(id_perfil=form.perfil_id.data)

        # Manually handle boolean fields first
        boolean_fields = ['htr1_p2', 'htr2', 'htr5', 'htr6', 'htr7', 'htr8_p2']
        for field_name in boolean_fields:
            setattr(ht_config, field_name, getattr(form, field_name).data if getattr(form, field_name).data is not None else False)

        form.populate_obj(ht_config)

        # Restore boolean fields after populate_obj
        for field_name in boolean_fields:
            setattr(ht_config, field_name, getattr(form, field_name).data if getattr(form, field_name).data is not None else False)

        db.session.add(ht_config)
        db.session.commit()

        log_audit('CREATE', 'tb_header_trailer', ht_config.id_header_trailer, f'Configuração HeaderTrailer criada para perfil: {perfil.perfil}')
        flash('Configuração HeaderTrailer criada com sucesso!', 'success')
        return redirect(url_for('list_headertrailer'))

    return render_template('functionalities/headertrailer_form.html', form=form, title='Nova Configuração HeaderTrailer')

@app.route('/funcionalidades/headertrailer/<int:id>/view')
@login_required
def view_headertrailer_config(id):
    ht_config = HeaderTrailer.query.get_or_404(id)
    if ht_config.is_deleted:
        abort(404)

    config_data = {
        'id': ht_config.id_header_trailer,
        'perfil': ht_config.perfil.perfil,
        'htr0_p1': ht_config.htr0_p1 or '',
        'htr0_p2': ht_config.htr0_p2 or '',
        'htr1_p1': ht_config.htr1_p1 or '',
        'htr1_p2': ht_config.htr1_p2 or False,
        'htr2': ht_config.htr2 or False,
        'htr3': ht_config.htr3 or '',
        'htr4': ht_config.htr4 or '',
        'htr5': ht_config.htr5 or False,
        'htr6': ht_config.htr6 or False,
        'htr7': ht_config.htr7 or False,
        'htr8_p1': ht_config.htr8_p1 or '',
        'htr8_p2': ht_config.htr8_p2 or False
    }
    return jsonify(config_data)

@app.route('/funcionalidades/headertrailer/<int:id>/editar', methods=['GET', 'POST'])
@login_required
def edit_headertrailer(id):
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_headertrailer'))

    ht_config = HeaderTrailer.query.get_or_404(id)
    if ht_config.is_deleted:
        abort(404)

    form = HeaderTrailerForm(obj=ht_config)
    # Populate choices for perfil_id field
    form.perfil_id.choices = [(p.id_perfil, p.perfil) for p in Perfil.query.filter_by(header_trailer=True, is_deleted=False).all()]
    form.perfil_id.data = ht_config.id_perfil

    if form.validate_on_submit():
        # Manually handle boolean fields first
        boolean_fields = ['htr1_p2', 'htr2', 'htr5', 'htr6', 'htr7', 'htr8_p2']
        for field_name in boolean_fields:
            setattr(ht_config, field_name, getattr(form, field_name).data if getattr(form, field_name).data is not None else False)

        form.populate_obj(ht_config)

        # Restore boolean fields after populate_obj
        for field_name in boolean_fields:
            setattr(ht_config, field_name, getattr(form, field_name).data if getattr(form, field_name).data is not None else False)

        db.session.commit()

        log_audit('UPDATE', 'tb_header_trailer', id, f'Configuração HeaderTrailer editada para perfil: {ht_config.perfil.perfil}')
        flash('Configuração HeaderTrailer atualizada com sucesso!', 'success')
        return redirect(url_for('list_headertrailer'))

    return render_template('functionalities/headertrailer_form.html', form=form, ht_config=ht_config, title='Editar Configuração HeaderTrailer')

@app.route('/funcionalidades/headertrailer/<int:id>/deletar', methods=['POST'])
@login_required
def delete_headertrailer(id):
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_headertrailer'))

    ht_config = HeaderTrailer.query.get_or_404(id)
    if ht_config.is_deleted:
        abort(404)

    ht_config.is_deleted = True
    db.session.commit()

    log_audit('DELETE', 'tb_header_trailer', id, f'Configuração HeaderTrailer deletada para perfil: {ht_config.perfil.perfil}')
    flash('Configuração HeaderTrailer deletada com sucesso!', 'success')
    return redirect(url_for('list_headertrailer'))

# JCL routes
@app.route('/funcionalidades/jcl')
@login_required
def list_jcl():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    search = request.args.get('search', '', type=str)

    query = db.session.query(JCL, Perfil).join(Perfil).filter(JCL.is_deleted == False)

    if search:
        search_pattern = f'%{search}%'
        query = query.filter(or_(
            Perfil.perfil.ilike(search_pattern),
            JCL.servidor.ilike(search_pattern),
            JCL.usuario.ilike(search_pattern)
        ))

    configs = query.order_by(Perfil.perfil).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return render_template('functionalities/jcl.html', configs=configs, search=search)

@app.route('/funcionalidades/jcl/novo', methods=['GET', 'POST'])
@login_required
def create_jcl():
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_jcl'))

    form = JCLForm()
    # Populate choices for perfil_id field
    perfis_jcl = Perfil.query.filter_by(jcl=True, is_deleted=False).all()
    form.perfil_id.choices = [(p.id_perfil, p.perfil) for p in perfis_jcl]

    # Pré-selecionar perfil (recém-criado ou visualizado)
    preselect_profile_id = session.get('last_created_profile_id') or session.get('current_viewing_profile_id')
    if preselect_profile_id and any(p.id_perfil == preselect_profile_id for p in perfis_jcl):
        form.perfil_id.data = preselect_profile_id
        # Remover apenas o perfil recém-criado da sessão após usar
        session.pop('last_created_profile_id', None)

    if form.validate_on_submit():
        perfil = Perfil.query.get(form.perfil_id.data)
        if not perfil or not perfil.jcl or perfil.is_deleted:
            flash('Perfil não permite configuração JCL.', 'danger')
            return redirect(url_for('list_jcl'))

        jcl_config = JCL(id_perfil=form.perfil_id.data)

        # Handle boolean field manually first
        jcl_config.dmz = form.dmz.data if form.dmz.data is not None else False

        form.populate_obj(jcl_config)

        # Restore boolean field after populate_obj
        jcl_config.dmz = form.dmz.data if form.dmz.data is not None else False

        db.session.add(jcl_config)
        db.session.commit()

        log_audit('CREATE', 'tb_jcl', jcl_config.id_jcl, f'Configuração JCL criada para perfil: {perfil.perfil}')
        flash('Configuração JCL criada com sucesso!', 'success')
        return redirect(url_for('list_jcl'))

    return render_template('functionalities/jcl_form.html', form=form, title='Nova Configuração JCL')

@app.route('/funcionalidades/jcl/<int:id>/view')
@login_required
def view_jcl_config(id):
    jcl_config = JCL.query.get_or_404(id)
    if jcl_config.is_deleted:
        abort(404)

    config_data = {
        'id': jcl_config.id_jcl,
        'perfil': jcl_config.perfil.perfil,
        'servidor': jcl_config.servidor or '',
        'usuario': jcl_config.usuario or '',
        'dmz': jcl_config.dmz or False
    }
    return jsonify(config_data)

@app.route('/funcionalidades/jcl/<int:id>/editar', methods=['GET', 'POST'])
@login_required
def edit_jcl(id):
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_jcl'))

    jcl_config = JCL.query.get_or_404(id)
    if jcl_config.is_deleted:
        abort(404)

    form = JCLForm(obj=jcl_config)
    # Populate choices for perfil_id field
    form.perfil_id.choices = [(p.id_perfil, p.perfil) for p in Perfil.query.filter_by(jcl=True, is_deleted=False).all()]
    form.perfil_id.data = jcl_config.id_perfil

    if form.validate_on_submit():
        # Handle boolean field manually first
        jcl_config.dmz = form.dmz.data if form.dmz.data is not None else False

        form.populate_obj(jcl_config)

        # Restore boolean field after populate_obj
        jcl_config.dmz = form.dmz.data if form.dmz.data is not None else False

        db.session.commit()

        log_audit('UPDATE', 'tb_jcl', id, f'Configuração JCL editada para perfil: {jcl_config.perfil.perfil}')
        flash('Configuração JCL atualizada com sucesso!', 'success')
        return redirect(url_for('list_jcl'))

    return render_template('functionalities/jcl_form.html', form=form, jcl_config=jcl_config, title='Editar Configuração JCL')

@app.route('/funcionalidades/jcl/<int:id>/deletar', methods=['POST'])
@login_required
def delete_jcl(id):
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_jcl'))

    jcl_config = JCL.query.get_or_404(id)
    if jcl_config.is_deleted:
        abort(404)

    jcl_config.is_deleted = True
    db.session.commit()

    log_audit('DELETE', 'tb_jcl', id, f'Configuração JCL deletada para perfil: {jcl_config.perfil.perfil}')
    flash('Configuração JCL deletada com sucesso!', 'success')
    return redirect(url_for('list_jcl'))

# PRM routes
@app.route('/funcionalidades/prm')
@login_required
def list_prm():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    search = request.args.get('search', '', type=str)

    query = db.session.query(PRM, Perfil).join(Perfil).filter(PRM.is_deleted == False)

    if search:
        search_pattern = f'%{search}%'
        query = query.filter(Perfil.perfil.ilike(search_pattern))

    configs = query.order_by(Perfil.perfil).paginate(
        page=page, per_page=per_page, error_out=False
    )

    # Buscar perfis com PRM habilitado para o dropdown
    perfis_prm = Perfil.query.filter_by(prm=True, is_deleted=False).all()

    return render_template('functionalities/prm.html', configs=configs, search=search, perfis_prm=perfis_prm)

@app.route('/funcionalidades/prm/novo', methods=['GET', 'POST'])
@login_required
def create_prm():
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_prm'))

    form = PRMForm()
    # Populate choices for perfil_id field
    perfis_prm = Perfil.query.filter_by(prm=True, is_deleted=False).all()
    form.perfil_id.choices = [(p.id_perfil, p.perfil) for p in perfis_prm]

    # Pré-selecionar perfil (recém-criado ou visualizado)
    preselect_profile_id = session.get('last_created_profile_id') or session.get('current_viewing_profile_id')
    if preselect_profile_id and any(p.id_perfil == preselect_profile_id for p in perfis_prm):
        form.perfil_id.data = preselect_profile_id
        # Remover apenas o perfil recém-criado da sessão após usar
        session.pop('last_created_profile_id', None)

    if form.validate_on_submit():
        perfil = Perfil.query.get(form.perfil_id.data)
        if not perfil or not perfil.prm or perfil.is_deleted:
            flash('Perfil não permite configuração PRM.', 'danger')
            return redirect(url_for('list_prm'))

        prm_config = PRM(id_perfil=form.perfil_id.data)

        # Manually handle boolean fields first
        boolean_fields = ['bpid', 'dd', 'dsu', 'dsl', 'dru', 'drl', 'mm', 'mru', 'mrl', 'msu', 'msl', 'aal', 'aau']
        for field_name in boolean_fields:
            setattr(prm_config, field_name, getattr(form, field_name).data if getattr(form, field_name).data is not None else False)

        form.populate_obj(prm_config)

        # Restore boolean fields after populate_obj
        for field_name in boolean_fields:
            setattr(prm_config, field_name, getattr(form, field_name).data if getattr(form, field_name).data is not None else False)

        db.session.add(prm_config)
        db.session.commit()

        log_audit('CREATE', 'tb_prm', prm_config.id_prm, f'Configuração PRM criada para perfil: {perfil.perfil}')
        flash('Configuração PRM criada com sucesso!', 'success')
        return redirect(url_for('list_prm'))

    return render_template('functionalities/prm_form.html', form=form, title='Nova Configuração PRM')

@app.route('/funcionalidades/prm/<int:id>/editar', methods=['GET', 'POST'])
@login_required
def edit_prm(id):
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_prm'))

    prm_config = PRM.query.get_or_404(id)
    if prm_config.is_deleted:
        abort(404)

    form = PRMForm(obj=prm_config)
    # Populate choices for perfil_id field
    form.perfil_id.choices = [(p.id_perfil, p.perfil) for p in Perfil.query.filter_by(prm=True, is_deleted=False).all()]
    form.perfil_id.data = prm_config.id_perfil

    if form.validate_on_submit():
        # Manually handle boolean fields first
        boolean_fields = ['bpid', 'dd', 'dsu', 'dsl', 'dru', 'drl', 'mm', 'mru', 'mrl', 'msu', 'msl', 'aal', 'aau']
        for field_name in boolean_fields:
            setattr(prm_config, field_name, getattr(form, field_name).data if getattr(form, field_name).data is not None else False)

        form.populate_obj(prm_config)

        # Restore boolean fields after populate_obj
        for field_name in boolean_fields:
            setattr(prm_config, field_name, getattr(form, field_name).data if getattr(form, field_name).data is not None else False)

        db.session.commit()

        log_audit('UPDATE', 'tb_prm', id, f'Configuração PRM editada para perfil: {prm_config.perfil.perfil}')
        flash('Configuração PRM atualizada com sucesso!', 'success')
        return redirect(url_for('list_prm'))

    return render_template('functionalities/prm_form.html', form=form, prm_config=prm_config, perfil=prm_config.perfil, title='Editar Configuração PRM')

@app.route('/funcionalidades/prm/<int:id>/visualizar')
@login_required
def view_prm(id):
    prm_config = PRM.query.get_or_404(id)
    if prm_config.is_deleted:
        abort(404)
    return render_template('functionalities/prm_view.html', prm_config=prm_config, title='Visualizar Configuração PRM')

@app.route('/funcionalidades/prm/<int:id>/view')
@login_required
def view_prm_config(id):
    prm_config = PRM.query.get_or_404(id)
    if prm_config.is_deleted:
        abort(404)

    # Build parameters list - show all fields (V0-V9/N0-N9)
    parametros = []
    for i in range(10):
        v_val = getattr(prm_config, f'v{i}', None)
        n_val = getattr(prm_config, f'n{i}', None)
        parametros.append({
            'indice': i,
            'valor': v_val or '',
            'nome': n_val or ''
        })

    # Build flags list - show all with status
    flag_mappings = {
        'bpid': 'BPID',
        'dd': 'DD',
        'dsu': 'DSU',
        'dsl': 'DSL',
        'dru': 'DRU',
        'drl': 'DRL',
        'mm': 'MM',
        'mru': 'MRU',
        'mrl': 'MRL',
        'msu': 'MSU',
        'msl': 'MSL',
        'aal': 'AAL',
        'aau': 'AAU'
    }

    flags = []
    for field, label in flag_mappings.items():
        flags.append({
            'nome': label,
            'ativo': getattr(prm_config, field, False)
        })

    prm_data = {
        'id': prm_config.id_prm,
        'perfil': prm_config.perfil.perfil,
        'perfil_id': prm_config.id_perfil,
        'parametros': parametros,
        'flags': flags,
        'criado_em': prm_config.created_at.strftime('%d/%m/%Y %H:%M') if hasattr(prm_config, 'created_at') and prm_config.created_at else '',
        'atualizado_em': prm_config.updated_at.strftime('%d/%m/%Y %H:%M') if hasattr(prm_config, 'updated_at') and prm_config.updated_at else ''
    }
    return jsonify(prm_data)

@app.route('/funcionalidades/prm/<int:id>/deletar', methods=['POST'])
@login_required
def delete_prm(id):
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_prm'))

    prm_config = PRM.query.get_or_404(id)
    if prm_config.is_deleted:
        abort(404)

    prm_config.is_deleted = True
    db.session.commit()

    log_audit('DELETE', 'tb_prm', id, f'Configuração PRM deletada para perfil: {prm_config.perfil.perfil}')
    flash('Configuração PRM deletada com sucesso!', 'success')
    return redirect(url_for('list_prm'))

# Advanced Search Routes
@app.route('/busca-avancada', methods=['GET', 'POST'])
@login_required
def advanced_search():
    # Define available tables with metadata and groups
    available_tables = [
        {'name': 'tb_perfil', 'display_name': 'Perfis', 'icon': 'fa-user-circle', 'description': 'Perfis de transferência', 'group': 'profiles'},
        {'name': 'tb_ftp', 'display_name': 'FTP', 'icon': 'fa-folder', 'description': 'Configurações FTP', 'group': 'protocols'},
        {'name': 'tb_scp', 'display_name': 'SCP', 'icon': 'fa-key', 'description': 'Configurações SCP', 'group': 'protocols'},
        {'name': 'tb_http', 'display_name': 'HTTP', 'icon': 'fa-globe', 'description': 'Configurações HTTP', 'group': 'protocols'},
        {'name': 'tb_s3', 'display_name': 'S3', 'icon': 'fa-cloud', 'description': 'Configurações Amazon S3', 'group': 'protocols'},
        {'name': 'tb_cd', 'display_name': 'Connect:Direct', 'icon': 'fa-link', 'description': 'Configurações Connect:Direct', 'group': 'protocols'},
        {'name': 'tb_jasppion', 'display_name': 'JASPPION', 'icon': 'fa-exchange-alt', 'description': 'Configurações JASPPION', 'group': 'protocols'},
        {'name': 'tb_mq', 'display_name': 'MQ', 'icon': 'fa-comments', 'description': 'Configurações IBM MQ', 'group': 'protocols'},
        {'name': 'tb_cmd', 'display_name': 'CMD', 'icon': 'fa-terminal', 'description': 'Configurações de comando', 'group': 'functionalities'},
        {'name': 'tb_formato', 'display_name': 'Formato', 'icon': 'fa-file-code', 'description': 'Configurações de formato', 'group': 'functionalities'},
        {'name': 'tb_header_trailer', 'display_name': 'Header/Trailer', 'icon': 'fa-file-alt', 'description': 'Configurações Header/Trailer', 'group': 'functionalities'},
        {'name': 'tb_jcl', 'display_name': 'JCL', 'icon': 'fa-code', 'description': 'Configurações JCL', 'group': 'functionalities'},
        {'name': 'tb_mail', 'display_name': 'Mail', 'icon': 'fa-envelope', 'description': 'Configurações de email', 'group': 'functionalities'},
        {'name': 'tb_prm', 'display_name': 'PRM', 'icon': 'fa-sliders-h', 'description': 'Configurações PRM', 'group': 'functionalities'},
        {'name': 'tb_ser', 'display_name': 'SER', 'icon': 'fa-server', 'description': 'Configurações SER', 'group': 'functionalities'},
        {'name': 'tb_traducao', 'display_name': 'Tradução', 'icon': 'fa-language', 'description': 'Configurações de tradução', 'group': 'functionalities'},
        {'name': 'tb_ftpusers', 'display_name': 'FTP Users', 'icon': 'fa-users', 'description': 'Usuários FTP', 'group': 'notifications'},
        {'name': 'tb_mailgroup', 'display_name': 'Mail Groups', 'icon': 'fa-envelope-open', 'description': 'Grupos de email', 'group': 'notifications'},
        {'name': 'tb_roscoe', 'display_name': 'ROSCOE', 'icon': 'fa-key', 'description': 'Configurações ROSCOE', 'group': 'notifications'},
    ]

    form = AdvancedSearchForm()

    results = {}
    search_performed = False
    total_results = 0
    search_term = None

    if form.validate_on_submit():
        search_term = form.search_term.data.strip()
        selected_tables = request.form.getlist('selected_tables')
        search_performed = True

        # Collect all results in a flat list
        all_results = []
        for table_name in selected_tables:
            table_results = perform_table_search(table_name, search_term)
            if table_results:
                all_results.extend(table_results)
                total_results += len(table_results)

        # Sort results by perfil, then by tabela
        all_results.sort(key=lambda x: (x['perfil'], x['tabela'], x['coluna']))
        results = all_results

    return render_template('search/advanced.html',
                         form=form,
                         available_tables=available_tables,
                         results=results,
                         search_performed=search_performed,
                         total_results=total_results,
                         search_term=search_term,
                         get_primary_key_for_table=get_primary_key_for_table)

def get_primary_key_for_table(table_name):
    """Get the primary key field name for a given table"""
    primary_keys = {
        'tb_perfil': 'id_perfil',
        'tb_ftp': 'id_ftp',
        'tb_scp': 'id_scp',
        'tb_http': 'id_http',
        'tb_s3': 'id_s3',
        'tb_cd': 'id_cd',
        'tb_jasppion': 'id_jasppion',
        'tb_mq': 'id_mq',
        'tb_cmd': 'id_cmd',
        'tb_formato': 'id_formato',
        'tb_header_trailer': 'id_header_trailer',
        'tb_jcl': 'id_jcl',
        'tb_mail': 'id_mail',
        'tb_prm': 'id_prm',
        'tb_ser': 'id_ser',
        'tb_traducao': 'id_traducao',
        'tb_ftpusers': 'id_ftpusers',
        'tb_mailgroup': 'id_mailgroup',
        'tb_roscoe': 'id_roscoe',
    }
    return primary_keys.get(table_name, 'id')

def perform_table_search(table_name, search_term):
    """Perform search in a specific table and return simplified results"""
    try:
        # Map table names to models
        table_models = {
            'tb_perfil': Perfil,
            'tb_ftp': FTP,
            'tb_scp': SCP,
            'tb_http': HTTP,
            'tb_s3': S3,
            'tb_cd': CD,
            'tb_jasppion': Jasppion,
            'tb_mq': MQ,
            'tb_cmd': CMD,
            'tb_formato': Formato,
            'tb_header_trailer': HeaderTrailer,
            'tb_jcl': JCL,
            'tb_mail': Mail,
            'tb_prm': PRM,
            'tb_ser': SER,
            'tb_traducao': Traducao,
            'tb_ftpusers': FTPUsers,
            'tb_mailgroup': MailGroup,
            'tb_roscoe': Roscoe,
        }

        # Map table names to display names
        table_display_names = {
            'tb_perfil': 'Perfis',
            'tb_ftp': 'FTP',
            'tb_scp': 'SCP',
            'tb_http': 'HTTP',
            'tb_s3': 'S3',
            'tb_cd': 'Connect:Direct',
            'tb_jasppion': 'JASPPION',
            'tb_mq': 'MQ',
            'tb_cmd': 'CMD',
            'tb_formato': 'Formato',
            'tb_header_trailer': 'Header/Trailer',
            'tb_jcl': 'JCL',
            'tb_mail': 'Mail',
            'tb_prm': 'PRM',
            'tb_ser': 'SER',
            'tb_traducao': 'Tradução',
            'tb_ftpusers': 'FTP Users',
            'tb_mailgroup': 'Mail Groups',
            'tb_roscoe': 'ROSCOE',
        }

        model = table_models.get(table_name)
        if not model:
            return []

        # Get all columns from the model
        columns = [column.name for column in model.__table__.columns]

        # Build search conditions for all text/string columns
        search_conditions = []
        search_pattern = f'%{search_term}%'

        for column_name in columns:
            column = getattr(model, column_name, None)
            if column is not None:
                # Only add ilike condition for text-based columns
                try:
                    # Check column type to ensure it's text-based
                    column_type = str(column.type).upper()
                    if any(text_type in column_type for text_type in ['VARCHAR', 'TEXT', 'CHAR', 'STRING']):
                        search_conditions.append(column.ilike(search_pattern))
                except Exception as e:
                    # Skip columns that cause errors
                    continue

        if not search_conditions:
            return []

        # Perform the search
        query = db.session.query(model).filter(or_(*search_conditions))

        # Add is_deleted filter if the model has it
        if hasattr(model, 'is_deleted'):
            query = query.filter(model.is_deleted == False)

        results = query.limit(50).all()  # Limit results to avoid performance issues

        # Convert results to simplified format: perfil, tabela, coluna, valor
        simplified_results = []
        table_display_name = table_display_names.get(table_name, table_name)

        for result in results:
            # Get perfil name if available
            perfil_name = '-'
            if table_name == 'tb_perfil' and hasattr(result, 'perfil'):
                perfil_name = getattr(result, 'perfil', '-')
            elif hasattr(result, 'perfil') and result.perfil and hasattr(result.perfil, 'perfil'):
                perfil_name = result.perfil.perfil
            elif table_name in ['tb_ftpusers', 'tb_mailgroup', 'tb_roscoe']:
                # These tables don't have perfil relationship
                perfil_name = '-'

            # Get primary key for record ID
            record_id = None
            primary_key_field = get_primary_key_for_table(table_name)
            if hasattr(result, primary_key_field):
                record_id = getattr(result, primary_key_field)

            # Check each column for matches
            for column_name in columns:
                column = getattr(model, column_name, None)
                if column is not None:
                    try:
                        # Only check text-based columns
                        column_type = str(column.type).upper()
                        if any(text_type in column_type for text_type in ['VARCHAR', 'TEXT', 'CHAR', 'STRING']):
                            value = getattr(result, column_name, None)
                            if value and search_term.lower() in str(value).lower():
                                # Format value
                                if hasattr(value, 'strftime'):
                                    formatted_value = value.strftime('%d/%m/%Y %H:%M:%S')
                                elif isinstance(value, bool):
                                    formatted_value = 'Sim' if value else 'Não'
                                else:
                                    formatted_value = str(value)

                                # Make column name more readable
                                readable_column = column_name.replace('_', ' ').title()
                                if readable_column.startswith('Id '):
                                    readable_column = 'ID ' + readable_column[3:]

                                simplified_results.append({
                                    'perfil': perfil_name,
                                    'tabela': table_display_name,
                                    'coluna': readable_column,
                                    'valor': formatted_value,
                                    'record_id': record_id,
                                    'table_name': table_name
                                })
                    except Exception as e:
                        continue

        return simplified_results

    except Exception as e:
        print(f"Erro ao buscar na tabela {table_name}: {str(e)}")
        return []

@app.route('/busca-avancada/detalhes/<table_name>/<int:record_id>')
@login_required
def get_record_details(table_name, record_id):
    """Get detailed information about a specific record"""
    try:
        # Map table names to models and their primary key fields
        table_info = {
            'tb_perfil': (Perfil, 'id_perfil'),
            'tb_ftp': (FTP, 'id_ftp'),
            'tb_scp': (SCP, 'id_scp'),
            'tb_http': (HTTP, 'id_http'),
            'tb_s3': (S3, 'id_s3'),
            'tb_cd': (CD, 'id_cd'),
            'tb_jasppion': (Jasppion, 'id_jasppion'),
            'tb_mq': (MQ, 'id_mq'),
            'tb_cmd': (CMD, 'id_cmd'),
            'tb_formato': (Formato, 'id_formato'),
            'tb_header_trailer': (HeaderTrailer, 'id_header_trailer'),
            'tb_jcl': (JCL, 'id_jcl'),
            'tb_mail': (Mail, 'id_mail'),
            'tb_prm': (PRM, 'id_prm'),
            'tb_ser': (SER, 'id_ser'),
            'tb_traducao': (Traducao, 'id_traducao'),
            'tb_ftpusers': (FTPUsers, 'id_ftpusers'),
            'tb_mailgroup': (MailGroup, 'id_mailgroup'),
            'tb_roscoe': (Roscoe, 'id_roscoe'),
        }

        if table_name not in table_info:
            return jsonify({'error': 'Tabela não encontrada'}), 404

        model, pk_field = table_info[table_name]
        record = db.session.query(model).filter(getattr(model, pk_field) == record_id).first()

        if not record:
            return jsonify({'error': 'Registro não encontrado'}), 404

        # Convert record to dictionary
        result_dict = {}
        for column in model.__table__.columns:
            column_name = column.name
            value = getattr(record, column_name, None)

            if value is not None:
                # Convert datetime to string
                if hasattr(value, 'strftime'):
                    value = value.strftime('%d/%m/%Y %H:%M:%S')
                # Convert boolean to Sim/Não
                elif isinstance(value, bool):
                    value = 'Sim' if value else 'Não'
                # Convert to string
                else:
                    value = str(value)
            else:
                value = '-'

            # Make column names more readable
            readable_name = column_name.replace('_', ' ').title()
            if readable_name.startswith('Id '):
                readable_name = 'ID ' + readable_name[3:]

            result_dict[readable_name] = value

        return jsonify(result_dict)

    except Exception as e:
        return jsonify({'error': f'Erro ao carregar detalhes: {str(e)}'}), 500

# Traducao routes
@app.route('/funcionalidades/traducao')
@login_required
def list_traducao():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    search = request.args.get('search', '', type=str)

    query = db.session.query(Traducao, Perfil).join(Perfil).filter(Traducao.is_deleted == False)

    if search:
        search_pattern = f'%{search}%'
        query = query.filter(or_(
            Perfil.perfil.ilike(search_pattern),
            Traducao.de.ilike(search_pattern),
            Traducao.para.ilike(search_pattern)
        ))

    configs = query.order_by(Perfil.perfil).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return render_template('functionalities/traducao.html', configs=configs, search=search)

@app.route('/funcionalidades/traducao/novo', methods=['GET', 'POST'])
@login_required
def create_traducao():
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_traducao'))

    form = TraducaoForm()
    # Populate choices for perfil_id field
    perfis_traducao = Perfil.query.filter_by(traducao=True, is_deleted=False).all()
    form.perfil_id.choices = [(p.id_perfil, p.perfil) for p in perfis_traducao]

    # Pré-selecionar perfil (recém-criado ou visualizado)
    preselect_profile_id = session.get('last_created_profile_id') or session.get('current_viewing_profile_id')
    if preselect_profile_id and any(p.id_perfil == preselect_profile_id for p in perfis_traducao):
        form.perfil_id.data = preselect_profile_id
        # Remover apenas o perfil recém-criado da sessão após usar
        session.pop('last_created_profile_id', None)

    if form.validate_on_submit():
        perfil = Perfil.query.get(form.perfil_id.data)
        if not perfil or not perfil.traducao or perfil.is_deleted:
            flash('Perfil não permite configuração Tradução.', 'danger')
            return redirect(url_for('list_traducao'))

        traducao_config = Traducao(id_perfil=form.perfil_id.data)
        form.populate_obj(traducao_config)

        db.session.add(traducao_config)
        db.session.commit()

        log_audit('CREATE', 'tb_traducao', traducao_config.id_traducao, f'Configuração Tradução criada para perfil: {perfil.perfil}')
        flash('Configuração Tradução criada com sucesso!', 'success')
        return redirect(url_for('list_traducao'))

    return render_template('functionalities/traducao_form.html', form=form, title='Nova Configuração Tradução')

@app.route('/funcionalidades/traducao/<int:id>/view')
@login_required
def view_traducao_config(id):
    traducao_config = Traducao.query.get_or_404(id)
    if traducao_config.is_deleted:
        abort(404)

    config_data = {
        'id': traducao_config.id_traducao,
        'perfil': traducao_config.perfil.perfil,
        'de': traducao_config.de or '',
        'para': traducao_config.para or ''
    }
    return jsonify(config_data)

@app.route('/funcionalidades/traducao/<int:id>/editar', methods=['GET', 'POST'])
@login_required
def edit_traducao(id):
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_traducao'))

    traducao_config = Traducao.query.get_or_404(id)
    if traducao_config.is_deleted:
        abort(404)

    form = TraducaoForm(obj=traducao_config)
    # Populate choices for perfil_id field
    form.perfil_id.choices = [(p.id_perfil, p.perfil) for p in Perfil.query.filter_by(traducao=True, is_deleted=False).all()]
    form.perfil_id.data = traducao_config.id_perfil

    if form.validate_on_submit():
        form.populate_obj(traducao_config)
        db.session.commit()

        log_audit('UPDATE', 'tb_traducao', id, f'Configuração Tradução editada para perfil: {traducao_config.perfil.perfil}')
        flash('Configuração Tradução atualizada com sucesso!', 'success')
        return redirect(url_for('list_traducao'))

    return render_template('functionalities/traducao_form.html', form=form, traducao_config=traducao_config, title='Editar Configuração Tradução')

@app.route('/funcionalidades/traducao/<int:id>/deletar', methods=['POST'])
@login_required
def delete_traducao(id):
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_traducao'))

    traducao_config = Traducao.query.get_or_404(id)
    if traducao_config.is_deleted:
        abort(404)

    traducao_config.is_deleted = True
    db.session.commit()

    log_audit('DELETE', 'tb_traducao', id, f'Configuração Tradução deletada para perfil: {traducao_config.perfil.perfil}')
    flash('Configuração Tradução deletada com sucesso!', 'success')
    return redirect(url_for('list_traducao'))

# SER routes
@app.route('/funcionalidades/ser')
@login_required
def list_ser():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    search = request.args.get('search', '', type=str)

    query = db.session.query(SER, Perfil).join(Perfil).filter(SER.is_deleted == False)

    if search:
        search_pattern = f'%{search}%'
        query = query.filter(or_(
            Perfil.perfil.ilike(search_pattern),
            SER.tit.ilike(search_pattern),
            SER.arquivo.ilike(search_pattern)
        ))

    configs = query.order_by(Perfil.perfil).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return render_template('functionalities/ser.html', configs=configs, search=search)

@app.route('/funcionalidades/ser/novo', methods=['GET', 'POST'])
@login_required
def create_ser():
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_ser'))

    form = SERForm()
    # Populate choices for perfil_id field
    perfis_ser = Perfil.query.filter_by(ser=True, is_deleted=False).all()
    form.perfil_id.choices = [(p.id_perfil, p.perfil) for p in perfis_ser]

    # Pré-selecionar perfil (recém-criado ou visualizado)
    preselect_profile_id = session.get('last_created_profile_id') or session.get('current_viewing_profile_id')
    if preselect_profile_id and any(p.id_perfil == preselect_profile_id for p in perfis_ser):
        form.perfil_id.data = preselect_profile_id
        # Remover apenas o perfil recém-criado da sessão após usar
        session.pop('last_created_profile_id', None)

    if form.validate_on_submit():
        perfil = Perfil.query.get(form.perfil_id.data)
        if not perfil or not perfil.ser or perfil.is_deleted:
            flash('Perfil não permite configuração SER.', 'danger')
            return redirect(url_for('list_ser'))

        ser_config = SER(id_perfil=form.perfil_id.data)

        # Handle boolean fields manually first
        boolean_fields = ['rel', 'mailc', 'def_', 'zip', 'crlf', 'msgsrg_env']
        for field_name in boolean_fields:
            setattr(ser_config, field_name, getattr(form, field_name).data if getattr(form, field_name).data is not None else False)

        form.populate_obj(ser_config)

        # Restore boolean fields after populate_obj
        for field_name in boolean_fields:
            setattr(ser_config, field_name, getattr(form, field_name).data if getattr(form, field_name).data is not None else False)

        db.session.add(ser_config)
        db.session.commit()

        log_audit('CREATE', 'tb_ser', ser_config.id_ser, f'Configuração SER criada para perfil: {perfil.perfil}')
        flash('Configuração SER criada com sucesso!', 'success')
        return redirect(url_for('list_ser'))

    return render_template('functionalities/ser_form.html', form=form, title='Nova Configuração SER')

@app.route('/funcionalidades/ser/<int:id>/view')
@login_required
def view_ser_config(id):
    ser_config = SER.query.get_or_404(id)
    if ser_config.is_deleted:
        abort(404)

    config_data = {
        'id': ser_config.id_ser,
        'perfil': ser_config.perfil.perfil,
        'tit': ser_config.tit or '',
        'arquivo': ser_config.arquivo or '',
        'rel': ser_config.rel or False,
        'mailc': ser_config.mailc or False,
        'def_flag': ser_config.def_flag or False,
        'zip': ser_config.zip or False,
        'crlf': ser_config.crlf or False,
        'msgsrg_env': ser_config.msgsrg_env or False
    }
    return jsonify(config_data)

@app.route('/funcionalidades/ser/<int:id>/editar', methods=['GET', 'POST'])
@login_required
def edit_ser(id):
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_ser'))

    ser_config = SER.query.get_or_404(id)
    if ser_config.is_deleted:
        abort(404)

    form = SERForm(obj=ser_config)
    # Populate choices for perfil_id field
    form.perfil_id.choices = [(p.id_perfil, p.perfil) for p in Perfil.query.filter_by(ser=True, is_deleted=False).all()]
    form.perfil_id.data = ser_config.id_perfil

    if form.validate_on_submit():
        # Handle boolean fields manually first
        boolean_fields = ['rel', 'mailc', 'def_', 'zip', 'crlf', 'msgsrg_env']
        for field_name in boolean_fields:
            setattr(ser_config, field_name, getattr(form, field_name).data if getattr(form, field_name).data is not None else False)

        form.populate_obj(ser_config)

        # Restore boolean fields after populate_obj
        for field_name in boolean_fields:
            setattr(ser_config, field_name, getattr(form, field_name).data if getattr(form, field_name).data is not None else False)

        db.session.commit()

        log_audit('UPDATE', 'tb_ser', id, f'Configuração SER editada para perfil: {ser_config.perfil.perfil}')
        flash('Configuração SER atualizada com sucesso!', 'success')
        return redirect(url_for('list_ser'))

    return render_template('functionalities/ser_form.html', form=form, ser_config=ser_config, title='Editar Configuração SER')

@app.route('/funcionalidades/ser/<int:id>/deletar', methods=['POST'])
@login_required
def delete_ser(id):
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_ser'))

    ser_config = SER.query.get_or_404(id)
    if ser_config.is_deleted:
        abort(404)

    ser_config.is_deleted = True
    db.session.commit()

    log_audit('DELETE', 'tb_ser', id, f'Configuração SER deletada para perfil: {ser_config.perfil.perfil}')
    flash('Configuração SER deletada com sucesso!', 'success')
    return redirect(url_for('list_ser'))

# Pendências
@app.route('/pendencias')
@login_required
def list_pendencias():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    search = request.args.get('search', '', type=str)
    status_filter = request.args.get('status_filter', '0', type=str)
    sort_field = request.args.get('sort', 'ordem', type=str)
    sort_direction = request.args.get('direction', 'asc', type=str)

    query = VWPendencias.query

    # Apply status filter
    if status_filter == '1':  # Pendentes (Status <> 0)
        query = query.filter(VWPendencias.status != '0')
    elif status_filter == '2':  # Detalhes (qualquer Status)
        # For Detalhes, we show all records regardless of status
        pass
    # For status_filter == '0' (Todos), no additional filter is applied

    # Apply search filter
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            db.or_(
                VWPendencias.bpname.ilike(search_term),
                VWPendencias.parent.ilike(search_term),
                VWPendencias.bpid.ilike(search_term),
                VWPendencias.destino.ilike(search_term),
                VWPendencias.arquivo.ilike(search_term)
            )
        )

    # Apply sorting
    valid_sort_fields = ['ordem', 'data', 'bpname', 'parent', 'bpid', 'destino', 'arquivo', 'basic_status', 'status']
    if sort_field not in valid_sort_fields:
        sort_field = 'ordem'

    if sort_direction not in ['asc', 'desc']:
        sort_direction = 'asc'

    # Get the column attribute from the model
    sort_column = getattr(VWPendencias, sort_field)

    if sort_direction == 'desc':
        query = query.order_by(sort_column.desc())
    else:
        query = query.order_by(sort_column.asc())

    pendencias = query.paginate(
        page=page,
        per_page=per_page,
        error_out=False
    )

    # Criar dicionário de perfis para linkagem na coluna Arquivo
    perfis = Perfil.query.filter_by(is_deleted=False).all()
    perfis_dict = {perfil.perfil: perfil for perfil in perfis}

    return render_template('pendencias/list.html',
                         pendencias=pendencias,
                         search=search,
                         status_filter=status_filter,
                         sort_field=sort_field,
                         sort_direction=sort_direction,
                         perfis_dict=perfis_dict)

# FAQ
@app.route('/faq')
@login_required
def list_faq():
    faqs = FAQ.query.filter_by(is_deleted=False).order_by(FAQ.categoria, FAQ.pergunta).all()

    # Agrupa FAQs por categoria
    faqs_by_category = {}
    for faq in faqs:
        if faq.categoria not in faqs_by_category:
            faqs_by_category[faq.categoria] = []
        faqs_by_category[faq.categoria].append(faq)

    return render_template('faq/list.html', faqs=faqs, faqs_by_category=faqs_by_category)

@app.route('/faq/categoria/<categoria>')
@login_required
def list_faq_by_category(categoria):
    faqs = FAQ.query.filter_by(categoria=categoria, is_deleted=False).order_by(FAQ.pergunta).all()

    # Agrupa FAQs por categoria (neste caso será só uma categoria)
    faqs_by_category = {categoria: faqs}

    return render_template('faq/list.html', faqs=faqs, faqs_by_category=faqs_by_category, categoria_filtrada=categoria)

@app.route('/faq/novo', methods=['GET', 'POST'])
@login_required
def create_faq():
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_faq'))

    # Busca categorias existentes
    categorias_existentes = db.session.query(FAQ.categoria).filter(
        FAQ.is_deleted == False,
        FAQ.categoria.isnot(None),
        FAQ.categoria != ''
    ).distinct().order_by(FAQ.categoria).all()
    categorias_existentes = [cat[0] for cat in categorias_existentes]

    form = FAQForm()
    if form.validate_on_submit():
        faq = FAQ(
            categoria=form.categoria.data,
            pergunta=form.pergunta.data,
            resposta=form.resposta.data,
            criado_por=current_user.username
        )

        # Handle image upload
        if form.imagem.data:
            filename = save_uploaded_file(form.imagem.data)
            if filename:
                faq.imagem_filename = filename

        db.session.add(faq)
        db.session.commit()

        log_audit('CREATE', 'tb_faq', faq.id, f'FAQ criado: {faq.pergunta}')
        flash('FAQ criado com sucesso!', 'success')
        return redirect(url_for('list_faq'))

    return render_template('faq/form.html', form=form, title='Criar FAQ', categorias_existentes=categorias_existentes)

@app.route('/faq/<int:id>/visualizar')
@login_required
def view_faq(id):
    faq = FAQ.query.get_or_404(id)
    if faq.is_deleted:
        abort(404)
    return render_template('faq/view.html', faq=faq)

@app.route('/faq/<int:id>/editar', methods=['GET', 'POST'])
@login_required
def edit_faq(id):
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_faq'))

    faq = FAQ.query.get_or_404(id)
    if faq.is_deleted:
        abort(404)

    # Busca categorias existentes
    categorias_existentes = db.session.query(FAQ.categoria).filter(
        FAQ.is_deleted == False,
        FAQ.categoria.isnot(None),
        FAQ.categoria != ''
    ).distinct().order_by(FAQ.categoria).all()
    categorias_existentes = [cat[0] for cat in categorias_existentes]

    form = FAQForm(obj=faq)
    if form.validate_on_submit():
        form.populate_obj(faq)

        # Handle image upload
        if form.imagem.data:
            filename = save_uploaded_file(form.imagem.data)
            if filename:
                faq.imagem_filename = filename

        db.session.commit()

        log_audit('UPDATE', 'tb_faq', id, f'FAQ editado: {faq.pergunta}')
        flash('FAQ atualizado com sucesso!', 'success')
        return redirect(url_for('list_faq'))

    return render_template('faq/form.html', form=form, faq=faq, title='Editar FAQ', categorias_existentes=categorias_existentes)

@app.route('/faq/<int:id>/deletar', methods=['POST'])
@login_required
def delete_faq(id):
    if not current_user.is_advanced():
        flash('Acesso negado.', 'danger')
        return redirect(url_for('list_faq'))

    faq = FAQ.query.get_or_404(id)
    if faq.is_deleted:
        abort(404)

    # Salva dados para restauração
    faq_data = {
        'categoria': faq.categoria,
        'pergunta': faq.pergunta,
        'resposta': faq.resposta,
        'imagem_filename': faq.imagem_filename
    }

    faq.is_deleted = True
    faq.deleted_data = json.dumps(faq_data)
    db.session.commit()

    # Salva os dados JSON no audit_log para restauração
    log_audit('DELETE', 'tb_faq', id, json.dumps(faq_data))
    flash('FAQ deletado com sucesso!', 'success')
    return redirect(url_for('list_faq'))

@app.route('/faq/categoria/<categoria>/deletar', methods=['POST'])
@login_required
def delete_category(categoria):
    if not current_user.is_advanced():
        return jsonify({'success': False, 'message': 'Acesso negado.'})

    try:
        # Busca todas as FAQs da categoria
        faqs = FAQ.query.filter_by(categoria=categoria, is_deleted=False).all()

        if not faqs:
            return jsonify({'success': False, 'message': 'Categoria não encontrada ou já está vazia.'})

        # Marca todas as FAQs da categoria como deletadas
        for faq in faqs:
            faq_data = {
                'categoria': faq.categoria,
                'pergunta': faq.pergunta,
                'resposta': faq.resposta,
                'imagem_filename': faq.imagem_filename
            }
            faq.is_deleted = True
            faq.deleted_data = json.dumps(faq_data)
            log_audit('DELETE', 'tb_faq', faq.id, f'FAQ deletado por exclusão de categoria: {categoria}')

        db.session.commit()

        # Log da exclusão da categoria
        log_audit('DELETE', 'faq_categoria', 0, f'Categoria deletada: {categoria} ({len(faqs)} FAQs removidos)')

        return jsonify({'success': True, 'message': f'Categoria "{categoria}" e {len(faqs)} FAQs deletados com sucesso!'})

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Erro ao deletar categoria: {str(e)}'})

# Gerenciamento de Categorias
@app.route('/faq/categorias')
@login_required
def list_categories():
    try:
        # Busca todas as categorias com contagem de FAQs
        categorias_query = db.session.query(
            FAQ.categoria,
            db.func.count(FAQ.id).label('total_faqs')
        ).filter(
            FAQ.is_deleted == False,
            FAQ.categoria.isnot(None),
            FAQ.categoria != ''
        ).group_by(FAQ.categoria).order_by(FAQ.categoria).all()

        categorias = [{'nome': cat[0], 'total_faqs': cat[1]} for cat in categorias_query]

        return render_template('faq/categories.html', categorias=categorias)
    except Exception as e:
        flash(f'Erro ao carregar categorias: {str(e)}', 'danger')
        return redirect(url_for('list_faq'))

@app.route('/faq/categorias/<categoria>/renomear', methods=['POST'])
@login_required
def rename_category(categoria):
    if not current_user.is_advanced():
        return jsonify({'success': False, 'message': 'Acesso negado.'})

    try:
        nova_categoria = request.json.get('nova_categoria', '').strip()

        if not nova_categoria:
            return jsonify({'success': False, 'message': 'Nome da categoria não pode estar vazio.'})

        if nova_categoria == categoria:
            return jsonify({'success': False, 'message': 'O novo nome deve ser diferente do atual.'})

        # Verifica se já existe categoria com o novo nome
        existing = FAQ.query.filter_by(categoria=nova_categoria, is_deleted=False).first()
        if existing:
            return jsonify({'success': False, 'message': 'Já existe uma categoria com este nome.'})

        # Atualiza todas as FAQs da categoria
        faqs = FAQ.query.filter_by(categoria=categoria, is_deleted=False).all()

        for faq in faqs:
            faq.categoria = nova_categoria
            log_audit('UPDATE', 'tb_faq', faq.id, f'Categoria renomeada de "{categoria}" para "{nova_categoria}"')

        db.session.commit()

        log_audit('UPDATE', 'faq_categoria', 0, f'Categoria renomeada: "{categoria}" -> "{nova_categoria}" ({len(faqs)} FAQs atualizados)')

        return jsonify({'success': True, 'message': f'Categoria renomeada de "{categoria}" para "{nova_categoria}" com sucesso!'})

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Erro ao renomear categoria: {str(e)}'})

# File serving
@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# API endpoints for real-time updates
@app.route('/api/stats')
@login_required
def api_stats():
    stats = get_statistics()
    return jsonify(stats)

@app.route('/api/activities')
@login_required
def api_activities():
    activities = get_recent_activities()
    return jsonify([{
        'usuario': a.usuario,
        'operacao': a.operacao,
        'tabela': a.tabela,
        'detalhes': a.detalhes,
        'data_hora': a.data_hora.strftime('%d/%m/%Y %H:%M')
    } for a in activities])

# LDAP Configuration routes
@app.route('/configuracoes/ldap', methods=['GET', 'POST'])
@login_required
def ldap_configuration():
    if not current_user.is_advanced():
        flash('Acesso negado. Apenas usuários avançados podem configurar LDAP.', 'danger')
        return redirect(url_for('configuration'))

    from ldap_auth import ldap_authenticator

    form = LDAPConfigForm()

    if form.validate_on_submit():
        # Salva as configurações LDAP
        ldap_configs = {
            'ldap_enabled': str(form.ldap_enabled.data).lower(),
            'ldap_server_uri': form.ldap_server_uri.data or '',
            'ldap_base_dn': form.ldap_base_dn.data or '',
            'ldap_bind_dn': form.ldap_bind_dn.data or '',
            'ldap_bind_password': form.ldap_bind_password.data or '',
            'ldap_user_search_filter': form.ldap_user_search_filter.data or '(cn={username})',
            'ldap_user_dn_template': form.ldap_user_dn_template.data or 'cn={username},{base_dn}',
            'ldap_group_search_base': form.ldap_group_search_base.data or '',
            'ldap_group_search_filter': form.ldap_group_search_filter.data or '(member={user_dn})',
            'ldap_admin_groups': form.ldap_admin_groups.data or '',
            'ldap_email_attribute': form.ldap_email_attribute.data or 'mail',
            'ldap_name_attribute': form.ldap_name_attribute.data or 'cn',
            'ldap_timeout': str(form.ldap_timeout.data or 10),
            'ldap_auto_create_users': str(form.ldap_auto_create_users.data).lower(),
            'ldap_sync_groups': str(form.ldap_sync_groups.data).lower(),
        }

        # Salva as configurações usando o utils
        from utils import save_config_values
        save_config_values(ldap_configs)

        # Atualiza o autenticador LDAP
        ldap_authenticator.__init__()

        log_audit('UPDATE', 'configuracoes', None, 'Configurações LDAP atualizadas')
        flash('Configurações LDAP salvas com sucesso!', 'success')
        return redirect(url_for('ldap_configuration'))

    # Carrega configurações atuais
    from utils import get_config_value
    form.ldap_enabled.data = get_config_value('ldap_enabled', 'false').lower() == 'true'
    form.ldap_server_uri.data = get_config_value('ldap_server_uri', '')
    form.ldap_base_dn.data = get_config_value('ldap_base_dn', '')
    form.ldap_bind_dn.data = get_config_value('ldap_bind_dn', '')
    form.ldap_bind_password.data = get_config_value('ldap_bind_password', '')
    form.ldap_user_search_filter.data = get_config_value('ldap_user_search_filter', '(cn={username})')
    form.ldap_user_dn_template.data = get_config_value('ldap_user_dn_template', 'cn={username},{base_dn}')
    form.ldap_group_search_base.data = get_config_value('ldap_group_search_base', '')
    form.ldap_group_search_filter.data = get_config_value('ldap_group_search_filter', '(member={user_dn})')
    form.ldap_admin_groups.data = get_config_value('ldap_admin_groups', '')
    form.ldap_email_attribute.data = get_config_value('ldap_email_attribute', 'mail')
    form.ldap_name_attribute.data = get_config_value('ldap_name_attribute', 'cn')
    form.ldap_timeout.data = int(get_config_value('ldap_timeout', '10'))
    form.ldap_auto_create_users.data = get_config_value('ldap_auto_create_users', 'true').lower() == 'true'
    form.ldap_sync_groups.data = get_config_value('ldap_sync_groups', 'true').lower() == 'true'

    return render_template('config/ldap.html', form=form)

@app.route('/configuracoes/ldap/testar', methods=['POST'])
@login_required
def test_ldap_connection():
    if not current_user.is_advanced():
        return jsonify({'success': False, 'message': 'Acesso negado'}), 403

    from ldap_auth import ldap_authenticator

    # Atualiza a configuração do autenticador
    ldap_authenticator.__init__()

    # Testa a conexão
    success, message = ldap_authenticator.test_connection()

    # Log da operação
    log_audit('TEST', 'configuracoes', None, f'Teste de conexão LDAP: {message}')

    return jsonify({
        'success': success,
        'message': message
    })

@app.route('/configuracoes/testar-oracle', methods=['POST'])
@login_required
def test_oracle_connection():
    if not current_user.is_advanced():
        return jsonify({'success': False, 'message': 'Acesso negado'}), 403

    try:
        # Get form data
        oracle_host = request.form.get('oracle_host', '').strip()
        oracle_port = request.form.get('oracle_port', '1521').strip()
        oracle_service = request.form.get('oracle_service', '').strip()
        oracle_username = request.form.get('oracle_username', '').strip()
        oracle_password = request.form.get('oracle_password', '').strip()
        oracle_schema = request.form.get('oracle_schema', '').strip()

        # Validate required fields
        if not all([oracle_host, oracle_service, oracle_username]):
            return jsonify({
                'success': False,
                'message': 'Host, Service Name e Username são obrigatórios'
            })

        # Build connection string
        if oracle_schema:
            connection_string = f"oracle+oracledb://{oracle_username}:{oracle_password}@{oracle_host}:{oracle_port}/{oracle_service}?schema={oracle_schema}"
        else:
            connection_string = f"oracle+oracledb://{oracle_username}:{oracle_password}@{oracle_host}:{oracle_port}/{oracle_service}"

        # Test connection
        from sqlalchemy import create_engine, text

        engine = create_engine(connection_string)

        # Try to connect and execute a simple query
        with engine.connect() as connection:
            result = connection.execute(text("SELECT 1 FROM DUAL"))
            result.fetchone()

        log_audit('TEST', 'configuracoes', None, f'Teste de conexão Oracle bem-sucedido: {oracle_username}@{oracle_host}:{oracle_port}/{oracle_service}')

        return jsonify({
            'success': True,
            'message': 'Conexão Oracle bem-sucedida!',
            'details': f'Conectado como {oracle_username}@{oracle_host}:{oracle_port}/{oracle_service}'
        })

    except Exception as e:
        error_message = str(e)
        log_audit('TEST', 'configuracoes', None, f'Teste de conexão Oracle falhou: {error_message}')

        return jsonify({
            'success': False,
            'message': 'Erro na conexão Oracle',
            'details': error_message
        })




@app.route('/configuracoes/download/codigo-fonte')
@login_required
def download_source_code():
    """Download complete source code as ZIP file"""
    try:
        # Create temporary file for the ZIP
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
        temp_file.close()

        # Get current directory (project root)
        project_root = os.getcwd()

        # Create ZIP file with all source code
        with zipfile.ZipFile(temp_file.name, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # Files and folders to include in the ZIP
            include_patterns = [
                '*.py', '*.html', '*.css', '*.js', '*.md', '*.txt', '*.toml', '*.lock',
                'templates', 'static', 'uploads'
            ]

            # Exclude patterns
            exclude_patterns = [
                '__pycache__', '.git', '.replit', 'node_modules', '.env',
                '*.pyc', '*.pyo', '.DS_Store', 'Thumbs.db'
            ]

            for root, dirs, files in os.walk(project_root):
                # Remove excluded directories
                dirs[:] = [d for d in dirs if not any(pattern in d for pattern in exclude_patterns)]

                for file in files:
                    # Skip excluded files
                    if any(pattern in file for pattern in exclude_patterns):
                        continue

                    file_path = os.path.join(root, file)
                    # Get relative path for ZIP
                    rel_path = os.path.relpath(file_path, project_root)

                    # Include file if it matches include patterns or is in included directories
                    should_include = False
                    for pattern in include_patterns:
                        if pattern.startswith('*') and file.endswith(pattern[1:]):
                            should_include = True
                            break
                        elif pattern in rel_path:
                            should_include = True
                            break

                    if should_include:
                        try:
                            zipf.write(file_path, rel_path)
                        except Exception as e:
                            app.logger.warning(f"Erro ao adicionar arquivo {rel_path} ao ZIP: {e}")

        # Get timestamp for filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"sistema_transferencia_{config.VERSION}_{timestamp}.zip"

        # Log the download
        log_audit('DOWNLOAD', 'sistema', None, f'Download do código fonte: {filename}')

        def remove_temp_file():
            try:
                os.unlink(temp_file.name)
            except:
                pass

        # Send file and schedule cleanup
        response = send_file(
            temp_file.name,
            as_attachment=True,
            download_name=filename,
            mimetype='application/zip'
        )

        # Schedule file cleanup after response
        @response.call_on_close
        def cleanup():
            remove_temp_file()

        return response

    except Exception as e:
        app.logger.error(f"Erro ao gerar ZIP do código fonte: {e}")
        flash(f'Erro ao gerar arquivo ZIP: {str(e)}', 'danger')
        return redirect(url_for('config_index'))

@app.route('/configuracoes/download/dump-banco')
@login_required
def download_database_dump():
    """Download complete database dump as SQL file for Oracle with full schema recreation"""
    try:
        # Create temporary file for the dump
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.sql', mode='w+', encoding='utf-8')

        # Write header
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        temp_file.write(f"-- ========================================\n")
        temp_file.write(f"-- {config.APP_FULL_NAME}\n")
        temp_file.write(f"-- DUMP COMPLETO ORACLE - RESTAURAÇÃO DO ZERO\n")
        temp_file.write(f"-- ========================================\n")
        temp_file.write(f"-- Gerado em: {timestamp}\n")
        temp_file.write(f"-- Usuário: {current_user.username}\n")
        temp_file.write(f"--\n")
        temp_file.write(f"-- INSTRUÇÕES DE IMPORTAÇÃO:\n")
        temp_file.write(f"-- 1. Conectar como usuário com privilégios DBA: sqlplus sys/password@host:porta/servico AS SYSDBA\n")
        temp_file.write(f"-- 2. Executar: @caminho_do_arquivo/dump.sql\n")
        temp_file.write(f"-- 3. Ou usar SQL*Plus: START dump.sql\n")
        temp_file.write(f"--\n")
        temp_file.write(f"-- ESTRUTURA DO DUMP:\n")
        temp_file.write(f"-- 1) Criação de tabelas\n")
        temp_file.write(f"-- 2) Inserção de registros (popular tabelas)\n")
        temp_file.write(f"-- 3) Criação de índices\n")
        temp_file.write(f"-- 4) Criação de sequences\n")
        temp_file.write(f"-- 5) Definição do valor atual das sequences\n")
        temp_file.write(f"-- 6) Criação de demais objetos (views, funções, triggers, constraints)\n")
        temp_file.write(f"--\n\n")

        # PASSO 1: CRIAÇÃO DE TABELAS
        temp_file.write("-- ========================================\n")
        temp_file.write("-- PASSO 1: CRIAÇÃO DE TABELAS\n")
        temp_file.write("-- ========================================\n\n")

        # Define all table structures
        table_definitions = {
            'usuarios': """
CREATE TABLE usuarios (
    id NUMBER(10) NOT NULL,
    username VARCHAR2(80) NOT NULL,
    email VARCHAR2(120) NOT NULL,
    password_hash VARCHAR2(256),
    user_type VARCHAR2(20) DEFAULT 'basico',
    is_active NUMBER(1) DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    auth_type VARCHAR2(20) DEFAULT 'local',
    ldap_dn VARCHAR2(500),
    ldap_groups CLOB,
    CONSTRAINT pk_usuarios PRIMARY KEY (id),
    CONSTRAINT uk_usuarios_username UNIQUE (username),
    CONSTRAINT uk_usuarios_email UNIQUE (email)
);""",
            'tb_perfil': """
CREATE TABLE tb_perfil (
    id_perfil NUMBER(10) NOT NULL,
    perfil VARCHAR2(60) NOT NULL,
    cad VARCHAR2(150),
    ass VARCHAR2(150),
    comentario VARCHAR2(400),
    header_trailer NUMBER(1) DEFAULT 0,
    prm NUMBER(1) DEFAULT 0,
    formato NUMBER(1) DEFAULT 0,
    traducao NUMBER(1) DEFAULT 0,
    scp NUMBER(1) DEFAULT 0,
    ftp NUMBER(1) DEFAULT 0,
    cd NUMBER(1) DEFAULT 0,
    cmd NUMBER(1) DEFAULT 0,
    jcl NUMBER(1) DEFAULT 0,
    ser NUMBER(1) DEFAULT 0,
    mail NUMBER(1) DEFAULT 0,
    http NUMBER(1) DEFAULT 0,
    jasppion NUMBER(1) DEFAULT 0,
    s3 NUMBER(1) DEFAULT 0,
    mq NUMBER(1) DEFAULT 0,
    diagram_filename VARCHAR2(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_deleted NUMBER(1) DEFAULT 0,
    CONSTRAINT pk_tb_perfil PRIMARY KEY (id_perfil),
    CONSTRAINT uk_tb_perfil_perfil UNIQUE (perfil)
);""",
            'tb_ftp': """
CREATE TABLE tb_ftp (
    id_ftp NUMBER(10) NOT NULL,
    id_perfil NUMBER(10) NOT NULL,
    servidor VARCHAR2(80),
    porta NUMBER(5) DEFAULT 21,
    usuario VARCHAR2(80),
    q_site VARCHAR2(200),
    comando VARCHAR2(20),
    dir_local VARCHAR2(100),
    dir_remoto VARCHAR2(100),
    arquivo_local VARCHAR2(100),
    arquivo_remoto VARCHAR2(100),
    cert VARCHAR2(60),
    zip NUMBER(1) DEFAULT 0,
    crlf NUMBER(1) DEFAULT 0,
    rel NUMBER(1) DEFAULT 0,
    bin NUMBER(1) DEFAULT 0,
    def NUMBER(1) DEFAULT 0,
    cdup NUMBER(1) DEFAULT 1,
    dmz NUMBER(1) DEFAULT 0,
    code NUMBER(1) DEFAULT 0,
    mail NUMBER(1) DEFAULT 0,
    mailmsg VARCHAR2(2000),
    mailass VARCHAR2(200),
    maildest VARCHAR2(1000),
    mailanexo NUMBER(1) DEFAULT 0,
    is_deleted NUMBER(1) DEFAULT 0,
    CONSTRAINT pk_tb_ftp PRIMARY KEY (id_ftp),
    CONSTRAINT fk_tb_ftp_perfil FOREIGN KEY (id_perfil) REFERENCES tb_perfil(id_perfil)
);""",
            'tb_scp': """
CREATE TABLE tb_scp (
    id_scp NUMBER(10) NOT NULL,
    id_perfil NUMBER(10) NOT NULL,
    servidor VARCHAR2(80),
    porta NUMBER(5) DEFAULT 22,
    usuario VARCHAR2(80),
    senha VARCHAR2(40),
    comando VARCHAR2(20),
    dir_local VARCHAR2(100),
    dir_remoto VARCHAR2(200),
    arquivo_local VARCHAR2(100),
    arquivo_remoto VARCHAR2(100),
    ssh VARCHAR2(400),
    ok VARCHAR2(800),
    nok VARCHAR2(800),
    tel VARCHAR2(40),
    pri NUMBER(10),
    zip NUMBER(1) DEFAULT 0,
    crlf NUMBER(1) DEFAULT 0,
    rel NUMBER(1) DEFAULT 0,
    bin NUMBER(1) DEFAULT 0,
    dmz NUMBER(1) DEFAULT 0,
    code NUMBER(1) DEFAULT 0,
    mail NUMBER(1) DEFAULT 0,
    mailmsg VARCHAR2(2000),
    mailass VARCHAR2(200),
    maildest VARCHAR2(1000),
    mailanexo NUMBER(1) DEFAULT 0,
    is_deleted NUMBER(1) DEFAULT 0,
    CONSTRAINT pk_tb_scp PRIMARY KEY (id_scp),
    CONSTRAINT fk_tb_scp_perfil FOREIGN KEY (id_perfil) REFERENCES tb_perfil(id_perfil)
);""",
            'tb_http': """
CREATE TABLE tb_http (
    id_http NUMBER(10) NOT NULL,
    id_perfil NUMBER(10) NOT NULL,
    dns VARCHAR2(80),
    porta VARCHAR2(10),
    uri VARCHAR2(80),
    metodo VARCHAR2(20),
    prms VARCHAR2(240),
    hash VARCHAR2(40),
    tipo_arq VARCHAR2(40),
    cert VARCHAR2(100),
    json VARCHAR2(1000),
    usuario VARCHAR2(80),
    dmz NUMBER(1) DEFAULT 0,
    mail NUMBER(1) DEFAULT 0,
    mailmsg VARCHAR2(2000),
    mailass VARCHAR2(200),
    maildest VARCHAR2(1000),
    mailanexo NUMBER(1) DEFAULT 0,
    is_deleted NUMBER(1) DEFAULT 0,
    CONSTRAINT pk_tb_http PRIMARY KEY (id_http),
    CONSTRAINT fk_tb_http_perfil FOREIGN KEY (id_perfil) REFERENCES tb_perfil(id_perfil)
);""",
            'tb_s3': """
CREATE TABLE tb_s3 (
    id_s3 NUMBER(10) NOT NULL,
    id_perfil NUMBER(10) NOT NULL,
    endpointurl VARCHAR2(100),
    endpointport VARCHAR2(10),
    bucketname VARCHAR2(100),
    action VARCHAR2(10),
    accesskey VARCHAR2(256),
    secretkey VARCHAR2(256),
    foldername VARCHAR2(100),
    filename VARCHAR2(100),
    localfilename VARCHAR2(100),
    header VARCHAR2(2000),
    acl VARCHAR2(2000),
    tag VARCHAR2(2000),
    ecs VARCHAR2(2000),
    region VARCHAR2(100),
    dmz NUMBER(1) DEFAULT 0,
    mail NUMBER(1) DEFAULT 0,
    mailmsg VARCHAR2(2000),
    mailass VARCHAR2(200),
    maildest VARCHAR2(1000),
    mailanexo NUMBER(1) DEFAULT 0,
    is_deleted NUMBER(1) DEFAULT 0,
    CONSTRAINT pk_tb_s3 PRIMARY KEY (id_s3),
    CONSTRAINT fk_tb_s3_perfil FOREIGN KEY (id_perfil) REFERENCES tb_perfil(id_perfil)
);""",
            'tb_cd': """
CREATE TABLE tb_cd (
    id_cd NUMBER(10) NOT NULL,
    id_perfil NUMBER(10) NOT NULL,
    aut VARCHAR2(60),
    dhd VARCHAR2(20),
    dst VARCHAR2(800),
    tit VARCHAR2(240),
    dsn VARCHAR2(800),
    dcb VARCHAR2(800),
    codbanco VARCHAR2(60),
    node VARCHAR2(400),
    tsk VARCHAR2(240),
    job VARCHAR2(240),
    spc VARCHAR2(100),
    dmz NUMBER(1) DEFAULT 1,
    disp VARCHAR2(60),
    sysopts VARCHAR2(800),
    opts VARCHAR2(800),
    mail NUMBER(1) DEFAULT 0,
    mailmsg VARCHAR2(2000),
    mailass VARCHAR2(200),
    maildest VARCHAR2(1000),
    mailanexo NUMBER(1) DEFAULT 0,
    is_deleted NUMBER(1) DEFAULT 0,
    CONSTRAINT pk_tb_cd PRIMARY KEY (id_cd),
    CONSTRAINT fk_tb_cd_perfil FOREIGN KEY (id_perfil) REFERENCES tb_perfil(id_perfil)
);""",
            'tb_jasppion': """
CREATE TABLE tb_jasppion (
    id_jasppion NUMBER(10) NOT NULL,
    id_perfil NUMBER(10) NOT NULL,
    servidor VARCHAR2(80),
    porta VARCHAR2(10),
    uri VARCHAR2(80),
    app VARCHAR2(4),
    fsadabas VARCHAR2(4),
    logon VARCHAR2(10),
    programa VARCHAR2(8),
    roscoe VARCHAR2(10),
    rcode VARCHAR2(4),
    delimitador VARCHAR2(60),
    mail NUMBER(1) DEFAULT 0,
    mailmsg VARCHAR2(2000),
    mailass VARCHAR2(200),
    maildest VARCHAR2(1000),
    mailanexo NUMBER(1) DEFAULT 0,
    is_deleted NUMBER(1) DEFAULT 0,
    CONSTRAINT pk_tb_jasppion PRIMARY KEY (id_jasppion),
    CONSTRAINT fk_tb_jasppion_perfil FOREIGN KEY (id_perfil) REFERENCES tb_perfil(id_perfil)
);""",
            'tb_mq': """
CREATE TABLE tb_mq (
    id_mq NUMBER(10) NOT NULL,
    id_perfil NUMBER(10) NOT NULL,
    hostname VARCHAR2(100) NOT NULL,
    port NUMBER(5) NOT NULL,
    channel VARCHAR2(100) NOT NULL,
    userid VARCHAR2(100) NOT NULL,
    passwd VARCHAR2(100),
    qmgr VARCHAR2(100),
    qname VARCHAR2(100),
    action VARCHAR2(20),
    gettype VARCHAR2(30),
    msgtype VARCHAR2(20),
    msgid VARCHAR2(20),
    ccsid VARCHAR2(20),
    ttl NUMBER(10),
    ssl NUMBER(1) DEFAULT 0,
    tls VARCHAR2(20),
    cert VARCHAR2(100),
    mail NUMBER(1) DEFAULT 0,
    mailmsg VARCHAR2(2000),
    mailass VARCHAR2(200),
    maildest VARCHAR2(1000),
    mailanexo NUMBER(1) DEFAULT 0,
    is_deleted NUMBER(1) DEFAULT 0,
    CONSTRAINT pk_tb_mq PRIMARY KEY (id_mq),
    CONSTRAINT fk_tb_mq_perfil FOREIGN KEY (id_perfil) REFERENCES tb_perfil(id_perfil)
);""",
            'tb_cmd': """
CREATE TABLE tb_cmd (
    id_cmd NUMBER(10) NOT NULL,
    id_perfil NUMBER(10) NOT NULL,
    comando VARCHAR2(400),
    is_deleted NUMBER(1) DEFAULT 0,
    CONSTRAINT pk_tb_cmd PRIMARY KEY (id_cmd),
    CONSTRAINT fk_tb_cmd_perfil FOREIGN KEY (id_perfil) REFERENCES tb_perfil(id_perfil)
);""",
            'tb_formato': """
CREATE TABLE tb_formato (
    id_formato NUMBER(10) NOT NULL,
    id_perfil NUMBER(10) NOT NULL,
    de VARCHAR2(40),
    para VARCHAR2(40),
    is_deleted NUMBER(1) DEFAULT 0,
    CONSTRAINT pk_tb_formato PRIMARY KEY (id_formato),
    CONSTRAINT fk_tb_formato_perfil FOREIGN KEY (id_perfil) REFERENCES tb_perfil(id_perfil)
);""",
            'tb_header_trailer': """
CREATE TABLE tb_header_trailer (
    id_header_trailer NUMBER(10) NOT NULL,
    id_perfil NUMBER(10) NOT NULL,
    htr0_p1 VARCHAR2(20),
    htr0_p2 VARCHAR2(20),
    htr1_p1 NUMBER(10),
    htr1_p2 NUMBER(1) DEFAULT 0,
    htr2 NUMBER(1) DEFAULT 0,
    htr3 VARCHAR2(20),
    htr4 VARCHAR2(20),
    htr5 NUMBER(1) DEFAULT 0,
    htr6 NUMBER(1) DEFAULT 0,
    htr7 NUMBER(1) DEFAULT 0,
    htr8_p1 VARCHAR2(400),
    htr8_p2 NUMBER(1) DEFAULT 0,
    htr9_p1 VARCHAR2(20),
    htr9_p2 VARCHAR2(20),
    htra VARCHAR2(20),
    is_deleted NUMBER(1) DEFAULT 0,
    CONSTRAINT pk_tb_header_trailer PRIMARY KEY (id_header_trailer),
    CONSTRAINT fk_tb_header_trailer_perfil FOREIGN KEY (id_perfil) REFERENCES tb_perfil(id_perfil)
);""",
            'tb_jcl': """
CREATE TABLE tb_jcl (
    id_jcl NUMBER(10) NOT NULL,
    id_perfil NUMBER(10) NOT NULL,
    servidor VARCHAR2(80),
    usuario VARCHAR2(80),
    jcl VARCHAR2(900),
    dmz NUMBER(1) DEFAULT 0,
    is_deleted NUMBER(1) DEFAULT 0,
    CONSTRAINT pk_tb_jcl PRIMARY KEY (id_jcl),
    CONSTRAINT fk_tb_jcl_perfil FOREIGN KEY (id_perfil) REFERENCES tb_perfil(id_perfil)
);""",
            'tb_mail': """
CREATE TABLE tb_mail (
    id_mail NUMBER(10) NOT NULL,
    id_perfil NUMBER(10) NOT NULL,
    msg VARCHAR2(2000),
    tit VARCHAR2(200),
    dest VARCHAR2(1000),
    anexo VARCHAR2(50),
    is_deleted NUMBER(1) DEFAULT 0,
    CONSTRAINT pk_tb_mail PRIMARY KEY (id_mail),
    CONSTRAINT fk_tb_mail_perfil FOREIGN KEY (id_perfil) REFERENCES tb_perfil(id_perfil)
);""",
            'tb_prm': """
CREATE TABLE tb_prm (
    id_prm NUMBER(10) NOT NULL,
    id_perfil NUMBER(10) NOT NULL,
    v0 VARCHAR2(20),
    v1 VARCHAR2(20),
    v2 VARCHAR2(20),
    v3 VARCHAR2(20),
    v4 VARCHAR2(20),
    v5 VARCHAR2(20),
    v6 VARCHAR2(20),
    v7 VARCHAR2(20),
    v8 VARCHAR2(20),
    v9 VARCHAR2(20),
    n0 VARCHAR2(20),
    n1 VARCHAR2(20),
    n2 VARCHAR2(20),
    n3 VARCHAR2(20),
    n4 VARCHAR2(20),
    n5 VARCHAR2(20),
    n6 VARCHAR2(20),
    n7 VARCHAR2(20),
    n8 VARCHAR2(20),
    n9 VARCHAR2(20),
    bpid NUMBER(1) DEFAULT 0,
    dd NUMBER(1) DEFAULT 0,
    dsu NUMBER(1) DEFAULT 0,
    dsl NUMBER(1) DEFAULT 0,
    dru NUMBER(1) DEFAULT 0,
    drl NUMBER(1) DEFAULT 0,
    mm NUMBER(1) DEFAULT 0,
    mru NUMBER(1) DEFAULT 0,
    mrl NUMBER(1) DEFAULT 0,
    msu NUMBER(1) DEFAULT 0,
    msl NUMBER(1) DEFAULT 0,
    aal NUMBER(1) DEFAULT 0,
    aau NUMBER(1) DEFAULT 0,
    is_deleted NUMBER(1) DEFAULT 0,
    CONSTRAINT pk_tb_prm PRIMARY KEY (id_prm),
    CONSTRAINT fk_tb_prm_perfil FOREIGN KEY (id_perfil) REFERENCES tb_perfil(id_perfil)
);""",
            'tb_traducao': """
CREATE TABLE tb_traducao (
    id_traducao NUMBER(10) NOT NULL,
    id_perfil NUMBER(10) NOT NULL,
    de VARCHAR2(100),
    para VARCHAR2(100),
    is_deleted NUMBER(1) DEFAULT 0,
    CONSTRAINT pk_tb_traducao PRIMARY KEY (id_traducao),
    CONSTRAINT fk_tb_traducao_perfil FOREIGN KEY (id_perfil) REFERENCES tb_perfil(id_perfil)
);""",
            'tb_ser': """
CREATE TABLE tb_ser (
    id_ser NUMBER(10) NOT NULL,
    id_perfil NUMBER(10) NOT NULL,
    rel NUMBER(1) DEFAULT 0,
    mailc NUMBER(1) DEFAULT 0,
    def NUMBER(1) DEFAULT 0,
    zip NUMBER(1) DEFAULT 0,
    crlf NUMBER(1) DEFAULT 0,
    msgsrg_env NUMBER(1) DEFAULT 0,
    aut VARCHAR2(100),
    tit VARCHAR2(200),
    arquivo VARCHAR2(100),
    dst_end VARCHAR2(1000),
    dst_roscoe VARCHAR2(200),
    dst_mailgroup VARCHAR2(200),
    msg VARCHAR2(800),
    is_deleted NUMBER(1) DEFAULT 0,
    CONSTRAINT pk_ser PRIMARY KEY (id_ser),
    CONSTRAINT fk_ser_perfil FOREIGN KEY (id_perfil) REFERENCES tb_perfil(id_perfil)
);""",
            'tb_ftpusers': """
CREATE TABLE tb_ftpusers (
    id_ftpusers NUMBER(10) NOT NULL,
    usuario VARCHAR2(100) NOT NULL,
    senha VARCHAR2(80),
    mf_unit VARCHAR2(20),
    is_deleted NUMBER(1) DEFAULT 0,
    CONSTRAINT pk_tb_ftpusers PRIMARY KEY (id_ftpusers),
    CONSTRAINT uk_tb_ftpusers_usuario UNIQUE (usuario)
);""",
            'tb_mailgroup': """
CREATE TABLE tb_mailgroup (
    id_mailgroup NUMBER(10) NOT NULL,
    grupo VARCHAR2(60),
    dst VARCHAR2(1000),
    is_deleted NUMBER(1) DEFAULT 0,
    CONSTRAINT pk_tb_mailgroup PRIMARY KEY (id_mailgroup)
);""",
            'tb_roscoe': """
CREATE TABLE tb_roscoe (
    id_roscoe NUMBER(10) NOT NULL,
    chave VARCHAR2(10),
    dst VARCHAR2(1000),
    is_deleted NUMBER(1) DEFAULT 0,
    CONSTRAINT pk_tb_roscoe PRIMARY KEY (id_roscoe)
);""",
            'audit_log': """
CREATE TABLE audit_log (
    id NUMBER(10) NOT NULL,
    usuario VARCHAR2(80),
    operacao VARCHAR2(20),
    tabela VARCHAR2(50),
    id_registro NUMBER(10),
    detalhes VARCHAR2(500),
    ip_origem VARCHAR2(45),
    data_hora TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_audit_log PRIMARY KEY (id)
);""",
            'faq': """
CREATE TABLE faq (
    id NUMBER(10) NOT NULL,
    categoria VARCHAR2(100),
    pergunta VARCHAR2(500),
    resposta CLOB,
    imagem_filename VARCHAR2(255),
    criado_por VARCHAR2(80),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_deleted NUMBER(1) DEFAULT 0,
    deleted_data CLOB,
    CONSTRAINT pk_faq PRIMARY KEY (id)
);""",
            'system_config': """
CREATE TABLE system_config (
    id NUMBER(10) NOT NULL,
    chave VARCHAR2(100),
    valor CLOB,
    descricao VARCHAR2(500),
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_system_config PRIMARY KEY (id),
    CONSTRAINT uk_system_config_chave UNIQUE (chave)
);""",
            'vw_pendencias': """
CREATE VIEW vw_pendencias AS
SELECT
    1 as ordem,
    TO_CHAR(SYSDATE, 'DD/MM/YYYY HH24:MI:SS') as data,
    'EXEMPLO_BP' as bpname,
    'PARENT_EXEMPLO' as parent,
    'BP001' as bpid,
    'destino_exemplo' as destino,
    'arquivo_exemplo.txt' as arquivo,
    'ACTIVE' as basic_status,
    '1' as status
FROM DUAL
WHERE 1=2;"""
        }

        # Create tables
        for table_name, table_sql in table_definitions.items():
            temp_file.write(f"-- Criando tabela {table_name}\n")
            temp_file.write(f"DROP TABLE {table_name} CASCADE CONSTRAINTS;\n")
            temp_file.write(f"{table_sql}\n\n")

        # PASSO 2: INSERÇÃO DE DADOS
        temp_file.write("-- ========================================\n")
        temp_file.write("-- PASSO 2: INSERÇÃO DE REGISTROS\n")
        temp_file.write("-- ========================================\n\n")

        # List of tables to export data from (in dependency order)
        system_tables = [
            'usuarios', 'tb_perfil', 'tb_ftp', 'tb_scp', 'tb_http', 'tb_s3',
            'tb_cd', 'tb_jasppion', 'tb_mq', 'tb_cmd', 'tb_formato', 'tb_header_trailer',
            'tb_jcl', 'tb_mail', 'tb_prm', 'tb_ser', 'tb_traducao',
            'tb_ftpusers', 'tb_mailgroup', 'tb_roscoe', 'system_config', 'faq', 'audit_log'
        ]

        for table_name in system_tables:
            try:
                # Get all data from table
                result = db.session.execute(text(f"SELECT * FROM {table_name}"))
                rows = result.fetchall()

                if rows:
                    temp_file.write(f"-- Dados da tabela {table_name} ({len(rows)} registros)\n")

                    # Get column names
                    columns = list(result.keys())

                    # Write INSERT statements with actual data
                    for row in rows:
                        values = []
                        for i, value in enumerate(row):
                            if value is None:
                                values.append('NULL')
                            elif isinstance(value, str):
                                # Escape single quotes for Oracle
                                escaped_value = value.replace("'", "''")
                                values.append(f"'{escaped_value}'")
                            elif isinstance(value, bool):
                                # Oracle uses 1/0 for boolean
                                values.append('1' if value else '0')
                            elif isinstance(value, datetime):
                                # Oracle timestamp format
                                values.append(f"TO_TIMESTAMP('{value.strftime('%Y-%m-%d %H:%M:%S')}', 'YYYY-MM-DD HH24:MI:SS')")
                            else:
                                values.append(str(value))

                        columns_str = ', '.join(columns)
                        values_str = ', '.join(values)
                        temp_file.write(f"INSERT INTO {table_name} ({columns_str}) VALUES ({values_str});\n")

                    temp_file.write(f"\n")
                else:
                    temp_file.write(f"-- Tabela {table_name} está vazia (0 registros)\n\n")

            except Exception as e:
                temp_file.write(f"-- ERRO AO EXPORTAR DADOS DA TABELA {table_name}: {str(e)}\n")
                import traceback
                temp_file.write(f"-- STACK TRACE: {traceback.format_exc()}\n\n")

        # PASSO 3: CRIAÇÃO DE ÍNDICES
        temp_file.write("-- ========================================\n")
        temp_file.write("-- PASSO 3: CRIAÇÃO DE ÍNDICES\n")
        temp_file.write("-- ========================================\n\n")

        # Define indexes with DROP statements
        indexes = [
            ("idx_usuarios_username", "usuarios", "username"),
            ("idx_usuarios_email", "usuarios", "email"),
            ("idx_usuarios_auth_type", "usuarios", "auth_type"),
            ("idx_tb_perfil_perfil", "tb_perfil", "perfil"),
            ("idx_tb_ftp_perfil", "tb_ftp", "id_perfil"),
            ("idx_tb_scp_perfil", "tb_scp", "id_perfil"),
            ("idx_tb_http_perfil", "tb_http", "id_perfil"),
            ("idx_tb_s3_perfil", "tb_s3", "id_perfil"),
            ("idx_tb_cd_perfil", "tb_cd", "id_perfil"),
            ("idx_tb_jasppion_perfil", "tb_jasppion", "id_perfil"),
            ("idx_tb_mq_perfil", "tb_mq", "id_perfil"),
            ("idx_tb_cmd_perfil", "tb_cmd", "id_perfil"),
            ("idx_tb_formato_perfil", "tb_formato", "id_perfil"),
            ("idx_tb_header_trailer_perfil", "tb_header_trailer", "id_perfil"),
            ("idx_tb_jcl_perfil", "tb_jcl", "id_perfil"),
            ("idx_tb_mail_perfil", "tb_mail", "id_perfil"),
            ("idx_tb_prm_perfil", "tb_prm", "id_perfil"),
            ("idx_tb_ser_perfil", "tb_ser", "id_perfil"),
            ("idx_tb_traducao_perfil", "tb_traducao", "id_perfil"),
            ("idx_audit_log_usuario", "audit_log", "usuario"),
            ("idx_audit_log_operacao", "audit_log", "operacao"),
            ("idx_audit_log_tabela", "audit_log", "tabela"),
            ("idx_audit_log_data_hora", "audit_log", "data_hora"),
            ("idx_faq_categoria", "faq", "categoria"),
            ("idx_system_config_chave", "system_config", "chave")
        ]

        for index_name, table_name, column_name in indexes:
            temp_file.write(f"-- Índice {index_name}\n")
            temp_file.write(f"BEGIN\n")
            temp_file.write(f"  EXECUTE IMMEDIATE 'DROP INDEX {index_name}';\n")
            temp_file.write(f"EXCEPTION\n")
            temp_file.write(f"  WHEN OTHERS THEN NULL;\n")
            temp_file.write(f"END;\n")
            temp_file.write(f"/\n")
            temp_file.write(f"CREATE INDEX {index_name} ON {table_name}({column_name});\n\n")
        temp_file.write(f"\n")

        # PASSO 4: CRIAÇÃO DE SEQUENCES
        temp_file.write("-- ========================================\n")
        temp_file.write("-- PASSO 4: CRIAÇÃO DE SEQUENCES\n")
        temp_file.write("-- ========================================\n\n")

        # Define sequences used by the system
        sequences_to_create = [
            ('usuarios_id_seq', 'usuarios', 'id'),
            ('tb_perfil_id_perfil_seq', 'tb_perfil', 'id_perfil'),
            ('tb_ftp_id_ftp_seq', 'tb_ftp', 'id_ftp'),
            ('tb_scp_id_scp_seq', 'tb_scp', 'id_scp'),
            ('tb_http_id_http_seq', 'tb_http', 'id_http'),
            ('tb_s3_id_s3_seq', 'tb_s3', 'id_s3'),
            ('tb_cd_id_cd_seq', 'tb_cd', 'id_cd'),
            ('tb_jasppion_id_jasppion_seq', 'tb_jasppion', 'id_jasppion'),
            ('tb_mq_id_mq_seq', 'tb_mq', 'id_mq'),
            ('tb_cmd_id_cmd_seq', 'tb_cmd', 'id_cmd'),
            ('tb_formato_id_formato_seq', 'tb_formato', 'id_formato'),
            ('tb_header_trailer_id_header_trailer_seq', 'tb_header_trailer', 'id_header_trailer'),
            ('tb_jcl_id_jcl_seq', 'tb_jcl', 'id_jcl'),
            ('tb_mail_id_mail_seq', 'tb_mail', 'id_mail'),
            ('tb_prm_id_prm_seq', 'tb_prm', 'id_prm'),
            ('tb_ser_id_ser_seq', 'tb_ser', 'id_ser'),
            ('tb_traducao_id_traducao_seq', 'tb_traducao', 'id_traducao'),
            ('tb_ftpusers_id_ftpusers_seq', 'tb_ftpusers', 'id_ftpusers'),
            ('tb_mailgroup_id_mailgroup_seq', 'tb_mailgroup', 'id_mailgroup'),
            ('tb_roscoe_id_roscoe_seq', 'tb_roscoe', 'id_roscoe'),
            ('audit_log_id_seq', 'audit_log', 'id'),
            ('faq_id_seq', 'faq', 'id'),
            ('system_config_id_seq', 'system_config', 'id')
        ]

        for seq_name, table_name, column_name in sequences_to_create:
            temp_file.write(f"-- Sequence para {table_name}\n")
            temp_file.write(f"DROP SEQUENCE {seq_name};\n")
            temp_file.write(f"CREATE SEQUENCE {seq_name}\n")
            temp_file.write(f"    START WITH 1\n")
            temp_file.write(f"    INCREMENT BY 1\n")
            temp_file.write(f"    NOMAXVALUE\n")
            temp_file.write(f"    NOCYCLE\n")
            temp_file.write(f"    CACHE 20;\n\n")

        # PASSO 5: DEFINIÇÃO DO VALOR ATUAL DAS SEQUENCES
        temp_file.write("-- ========================================\n")
        temp_file.write("-- PASSO 5: ATUALIZAÇÃO DOS VALORES DAS SEQUENCES\n")
        temp_file.write("-- ========================================\n\n")

        for seq_name, table_name, column_name in sequences_to_create:
            try:
                # Check if table exists and has data
                result = db.session.execute(text(f"SELECT COUNT(*) FROM {table_name}"))
                count = result.fetchone()[0]

                if count > 0:
                    # Get max ID value
                    max_result = db.session.execute(text(f"SELECT NVL(MAX({column_name}), 0) FROM {table_name}"))
                    max_id = max_result.fetchone()[0]
                    next_val = max_id + 1

                    temp_file.write(f"-- Ajustar sequence {seq_name} para próximo valor: {next_val}\n")
                    temp_file.write(f"DECLARE\n")
                    temp_file.write(f"  l_val NUMBER;\n")
                    temp_file.write(f"BEGIN\n")
                    temp_file.write(f"  EXECUTE IMMEDIATE 'SELECT {seq_name}.NEXTVAL FROM DUAL' INTO l_val;\n")
                    temp_file.write(f"  EXECUTE IMMEDIATE 'ALTER SEQUENCE {seq_name} INCREMENT BY ' || ({next_val} - l_val);\n")
                    temp_file.write(f"  EXECUTE IMMEDIATE 'SELECT {seq_name}.NEXTVAL FROM DUAL' INTO l_val;\n")
                    temp_file.write(f"  EXECUTE IMMEDIATE 'ALTER SEQUENCE {seq_name} INCREMENT BY 1';\n")
                    temp_file.write(f"END;\n")
                    temp_file.write(f"/\n\n")
                else:
                    temp_file.write(f"-- Sequence {seq_name} mantém valor inicial (tabela {table_name} vazia)\n\n")

            except Exception as e:
                temp_file.write(f"-- ERRO AO AJUSTAR SEQUENCE {seq_name}: {str(e)}\n\n")

        # PASSO 6: CRIAÇÃO DE OBJETOS ADICIONAIS
        temp_file.write("-- ========================================\n")
        temp_file.write("-- PASSO 6: CRIAÇÃO DE OBJETOS ADICIONAIS\n")
        temp_file.write("-- ========================================\n\n")

        # Triggers para atualização automática de timestamps
        triggers = [
            """-- Trigger para atualizar updated_at em tb_perfil
CREATE OR REPLACE TRIGGER trg_tb_perfil_updated_at
    BEFORE UPDATE ON tb_perfil
    FOR EACH ROW
BEGIN
    :NEW.updated_at := CURRENT_TIMESTAMP;
END;
/""",
            """-- Trigger para atualizar updated_at em system_config
CREATE OR REPLACE TRIGGER trg_system_config_updated_at
    BEFORE UPDATE ON system_config
    FOR EACH ROW
BEGIN
    :NEW.updated_at := CURRENT_TIMESTAMP;
END;
/"""
        ]

        for trigger_sql in triggers:
            temp_file.write(f"{trigger_sql}\n\n")

        # Functions úteis
        functions = [
            """-- Função para verificar se usuário é administrador
CREATE OR REPLACE FUNCTION is_admin_user(p_username VARCHAR2)
RETURN NUMBER
IS
    v_count NUMBER;
BEGIN
    SELECT COUNT(*)
    INTO v_count
    FROM usuarios
    WHERE username = p_username
    AND user_type IN ('admin', 'avancado')
    AND is_active = 1;

    RETURN v_count;
END;
/""",
            """-- Função para contar perfis ativos
CREATE OR REPLACE FUNCTION count_active_profiles
RETURN NUMBER
IS
    v_count NUMBER;
BEGIN
    SELECT COUNT(*)
    INTO v_count
    FROM tb_perfil
    WHERE is_deleted = 0;

    RETURN v_count;
END;
/"""
        ]

        for function_sql in functions:
            temp_file.write(f"{function_sql}\n\n")

        # Additional constraints
        temp_file.write("-- Constraints adicionais\n")
        constraints = [
            "ALTER TABLE usuarios ADD CONSTRAINT chk_usuarios_user_type CHECK (user_type IN ('basico', 'avancado', 'admin'));",
            "ALTER TABLE usuarios ADD CONSTRAINT chk_usuarios_auth_type CHECK (auth_type IN ('local', 'ldap'));",
            "ALTER TABLE audit_log ADD CONSTRAINT chk_audit_operacao CHECK (operacao IN ('CREATE', 'UPDATE', 'DELETE', 'RESTORE', 'LOGIN', 'LOGOUT', 'TEST', 'DOWNLOAD'));"
        ]

        for constraint_sql in constraints:
            temp_file.write(f"{constraint_sql}\n")

        temp_file.write(f"\n")

        # COMMIT FINAL
        temp_file.write("-- ========================================\n")
        temp_file.write("-- COMMIT FINAL\n")
        temp_file.write("-- ========================================\n")
        temp_file.write("COMMIT;\n\n")

        # Final completion message
        temp_file.write("-- ========================================\n")
        temp_file.write("-- RESTAURAÇÃO COMPLETA\n")
        temp_file.write("-- ========================================\n")
        temp_file.write("-- Banco de dados Oracle restaurado com sucesso!\n")
        temp_file.write("-- \n")
        temp_file.write("-- ESTRUTURA CRIADA:\n")
        temp_file.write("-- ✓ 1) Criação de tabelas\n")
        temp_file.write("-- ✓ 2) Inserção de registros (popular tabelas)\n")
        temp_file.write("-- ✓ 3) Criação de índices\n")
        temp_file.write("-- ✓ 4) Criação de sequences\n")
        temp_file.write("-- ✓ 5) Definição do valor atual das sequences\n")
        temp_file.write("-- ✓ 6) Criação de demais objetos (views, funções, triggers, constraints)\n")
        temp_file.write("-- \n")
        temp_file.write("-- Sistema pronto para uso!\n")

        # Add footer
        temp_file.write(f"\n\n-- Fim do dump Oracle completo - {timestamp}\n")
        temp_file.write(f"-- Total de tabelas: {len(table_definitions)}\n")
        temp_file.write(f"-- Total de sequences: {len(sequences_to_create)}\n")
        temp_file.write(f"-- Total de índices: {len(indexes)}\n")
        temp_file.write(f"-- Total de triggers: {len(triggers)}\n")
        temp_file.write(f"-- Total de funções: {len(functions)}\n")

        # Close and reopen for reading
        temp_file.close()

        # Generate filename
        timestamp_file = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"sistema_transferencia_oracle_completo_{timestamp_file}.sql"

        # Log the download
        log_audit('DOWNLOAD', 'database', None, f'Download do dump Oracle completo: {filename}')

        def remove_temp_file():
            try:
                os.unlink(temp_file.name)
            except:
                pass

        # Send file
        response = send_file(
            temp_file.name,
            as_attachment=True,
            download_name=filename,
            mimetype='application/sql'
        )

        # Schedule file cleanup after response
        @response.call_on_close
        def cleanup():
            remove_temp_file()

        return response

    except Exception as e:
        app.logger.error(f"Erro ao gerar dump completo do banco Oracle: {e}")
        flash(f'Erro ao gerar dump completo do banco Oracle: {str(e)}', 'danger')
        return redirect(url_for('configuration'))

@app.route('/configuracoes/download/documentacao')
@login_required
def download_documentation():
    """Download system documentation as PDF"""
    try:
        # Create temporary file for the documentation
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.html', mode='w+', encoding='utf-8')

        # Generate HTML content for the documentation
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        html_content = f"""
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sistema de Transferência de Arquivos v2.1.2 - Documentação</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 40px;
            color: #333;
        }}
        h1, h2, h3 {{
            color: #2c3e50;
        }}
        h1 {{
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }}
        h2 {{
            border-bottom: 1px solid #bdc3c7;
            padding-bottom: 5px;
            margin-top: 30px;
        }}
        .header {{
            text-align: center;
            margin-bottom: 40px;
        }}
        .section {{
            margin-bottom: 30px;
        }}
        .protocol-list, .feature-list {{
            background-color: #f8f9fa;
            padding: 15px;
            border-left: 4px solid #3498db;
            margin: 15px 0;
        }}
        .protocol-list ul, .feature-list ul {{
            margin: 0;
            padding-left: 20px;
        }}
        .footer {{
            margin-top: 50px;
            text-align: center;
            color: #7f8c8d;
            border-top: 1px solid #bdc3c7;
            padding-top: 20px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
        }}
        th {{
            background-color: #3498db;
            color: white;
        }}
        .code {{
            background-color: #f4f4f4;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: monospace;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Sistema de Transferência de Arquivos</h1>
        <h2>Versão 2.1.2</h2>
        <p><strong>Documentação Técnica Completa</strong></p>
        <p>Gerado em: {timestamp} por {current_user.username}</p>
    </div>

    <div class="section">
        <h2>1. Visão Geral do Sistema</h2>
        <p>O Sistema de Transferência de Arquivos é uma aplicação web desenvolvida em Python/Flask que oferece gerenciamento abrangente de serviços de transferência de arquivos através de múltiplos protocolos.</p>

        <h3>Características Principais:</h3>
        <ul>
            <li>Suporte a múltiplos protocolos de transferência</li>
            <li>Autenticação dual (local e LDAP/Active Directory)</li>
            <li>Interface web responsiva em português brasileiro</li>
            <li>Sistema de auditoria completo</li>
            <li>Gestão avançada de perfis e configurações</li>
            <li>Busca avançada em múltiplas tabelas</li>
        </ul>
    </div>

    <div class="section">
        <h2>2. Protocolos Suportados</h2>
        <div class="protocol-list">
            <h3>Protocolos de Transferência:</h3>
            <ul>
                <li><strong>FTP</strong> - File Transfer Protocol para transferências básicas</li>
                <li><strong>SCP</strong> - Secure Copy Protocol via SSH</li>
                <li><strong>HTTP/HTTPS</strong> - Transferências web com autenticação</li>
                <li><strong>S3</strong> - Amazon Simple Storage Service</li>
                <li><strong>Connect:Direct</strong> - Solução IBM para transferências corporativas</li>
                <li><strong>JASPPION</strong> - Integração com sistemas mainframe de pagamento</li>
            </ul>
        </div>
    </div>

    <div class="section">
        <h2>3. Funcionalidades do Sistema</h2>
        <div class="feature-list">
            <h3>Módulos de Funcionalidades:</h3>
            <ul>
                <li><strong>CMD</strong> - Configurações de comandos do sistema</li>
                <li><strong>Formato</strong> - Definições de formatos de arquivo</li>
                <li><strong>Header/Trailer</strong> - Configurações de cabeçalhos e rodapés</li>
                <li><strong>JCL</strong> - Job Control Language para mainframe</li>
                <li><strong>Mail</strong> - Configurações de email</li>
                <li><strong>PRM</strong> - Parâmetros do sistema</li>
                <li><strong>SER</strong> - Configurações de serviços</li>
                <li><strong>Tradução</strong> - Mapeamento e tradução de dados</li>
            </ul>
        </div>
    </div>

    <div class="section">
        <h2>4. Sistema de Notificações</h2>
        <table>
            <thead>
                <tr>
                    <th>Módulo</th>
                    <th>Descrição</th>
                    <th>Função</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td>FTP Users</td>
                    <td>Gestão de usuários FTP</td>
                    <td>Controle de acesso e permissões</td>
                </tr>
                <tr>
                    <td>Mail Group</td>
                    <td>Grupos de email</td>
                    <td>Distribuição de notificações</td>
                </tr>
                <tr>
                    <td>Roscoe</td>
                    <td>Interface mainframe</td>
                    <td>Integração com sistemas legados</td>
                </tr>
            </tbody>
        </table>
    </div>

    <div class="section">
        <h2>5. Autenticação e Segurança</h2>
        <h3>Métodos de Autenticação:</h3>
        <ul>
            <li><strong>Local</strong> - Usuários criados no sistema com senha hash</li>
            <li><strong>LDAP/Active Directory</strong> - Integração com domínio corporativo</li>
        </ul>

        <h3>Níveis de Usuário:</h3>
        <ul>
            <li><strong>Básico</strong> - Consulta e visualização</li>
            <li><strong>Avançado</strong> - Criação, edição e exclusão</li>
        </ul>

        <h3>Recursos de Segurança:</h3>
        <ul>
            <li>Proteção CSRF em todos os formulários</li>
            <li>Validação de uploads de arquivo</li>
            <li>Hash seguro de senhas</li>
            <li>Autenticação baseada em sessão</li>
            <li>Logs de auditoria detalhados</li>
        </ul>
    </div>

    <div class="section">
        <h2>6. Busca Avançada</h2>
        <p>O sistema oferece funcionalidade de busca avançada que permite:</p>
        <ul>
            <li>Pesquisa em múltiplas tabelas simultaneamente</li>
            <li>Seleção específica de tabelas via checkboxes</li>
            <li>Busca em campos de texto (VARCHAR, TEXT, CHAR)</li>
            <li>Resultados destacados com termo pesquisado</li>
            <li>Modal detalhado para visualização de registros</li>
        </ul>
    </div>

    <div class="section">
        <h2>7. Configurações do Sistema</h2>
        <h3>Opções de Configuração:</h3>
        <ul>
            <li><strong>Banco de Dados</strong> - Configurações de conexão Oracle</li>
            <li><strong>Servidor</strong> - Configurações de aplicação e logs</li>
            <li><strong>Segurança</strong> - Políticas de senha e sessão</li>
            <li><strong>LDAP</strong> - Configurações de Active Directory</li>
        </ul>

        <h3>Downloads Disponíveis:</h3>
        <ul>
            <li><strong>Código Fonte (ZIP)</strong> - Todos os arquivos do sistema</li>
            <li><strong>Dump Banco (SQL)</strong> - Backup completo do banco de dados</li>
            <li><strong>Documentação (HTML)</strong> - Este documento</li>
        </ul>
    </div>

    <div class="section">
        <h2>8. Estrutura Técnica</h2>
        <h3>Backend:</h3>
        <ul>
            <li>Framework: Flask (Python)</li>
            <li>ORM: SQLAlchemy</li>
            <li>Banco: Oracle</li>
            <li>Autenticação: Flask-Login</li>
            <li>Formulários: Flask-WTF + WTForms</li>
        </ul>

        <h3>Frontend:</h3>
        <ul>
            <li>Template Engine: Jinja2</li>
            <li>CSS Framework: Bootstrap 5</li>
            <li>Ícones: Font Awesome</li>
            <li>JavaScript: jQuery para interações dinâmicas</li>
        </ul>
    </div>

    <div class="section">
        <h2>9. Funcionalidades Especiais</h2>
        <h3>Gestão de Perfis:</h3>
        <ul>
            <li>Criação e duplicação de perfis</li>
            <li>Flags de protocolo para ativação seletiva</li>
            <li>Upload de diagramas e documentação</li>
            <li>Verificação de dependências antes da exclusão</li>
        </ul>

        <h3>Sistema de Auditoria:</h3>
        <ul>
            <li>Log de todas as operações (CREATE, UPDATE, DELETE)</li>
            <li>Rastreamento de usuário e timestamp</li>
            <li>Funcionalidade de restauração de dados</li>
            <li>Validação de integridade referencial</li>
        </ul>
    </div>

    <div class="section">
        <h2>10. FAQ e Suporte</h2>
        <p>O sistema inclui um módulo de FAQ (Perguntas Frequentes) com:</p>
        <ul>
            <li>Categorização de perguntas</li>
            <li>Rastreamento de criador e data</li>
            <li>Interface de pesquisa</li>
            <li>Edição para usuários avançados</li>
        </ul>
    </div>

    <div class="footer">
        <p><strong>Sistema de Transferência de Arquivos v2.1.1</strong></p>
        <p>Desenvolvido com Flask • Oracle • Bootstrap</p>
        <p>Documentação gerada automaticamente em {timestamp}</p>
    </div>
</body>
</html>
        """

        # Write HTML content
        temp_file.write(html_content)
        temp_file.close()

        # Generate filename
        timestamp_file = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"sistema_transferencia_doc_{timestamp_file}.html"

        # Log the download
        log_audit('DOWNLOAD', 'documentacao', None, f'Download da documentação: {filename}')

        def remove_temp_file():
            try:
                os.unlink(temp_file.name)
            except:
                pass

        # Send file
        response = send_file(
            temp_file.name,
            as_attachment=True,
            download_name=filename,
            mimetype='text/html'
        )

        # Schedule file cleanup after response
        @response.call_on_close
        def cleanup():
            remove_temp_file()

        return response

    except Exception as e:
        app.logger.error(f"Erro ao gerar documentação: {e}")
        flash(f'Erro ao gerar documentação: {str(e)}', 'danger')
        return redirect(url_for('config_index'))