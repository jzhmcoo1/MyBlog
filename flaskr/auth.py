import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from flaskr.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')


@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None

        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'
        elif db.execute(
                'SELECT id FROM user WHERE username = ?', (username,)
        ).fetchone() is not None:
            error = 'User {} is already registered.'.format(username)

        if error is None:
            db.execute(
                'INSERT INTO user (username, password) VALUES (?, ?)',
                (username, generate_password_hash(password))
            )
            db.commit()
            return redirect(url_for('auth.login'))

        flash(error)

    return render_template('auth/register.html')


@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM user WHERE username = ?', (username,)
        ).fetchone()

        if user is None:
            error = 'Incorrect username.'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password.'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('index'))

        flash(error)

    return render_template('auth/login.html')


# 检查用户 id 是否已经存储在 session 中,并从数据库中获取用户数据
@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()


# 注销
@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view


def get_info(id):
    db = get_db()
    user_info = db.execute(
        'SELECT u.id, username, nickname, address, description '
        ' FROM user u'
        ' WHERE u.id = ?',
        (id,)
    ).fetchone()
    return user_info


def get_recent_ten_posts(id):
    db = get_db()
    query = 'select id, author_id, created, title, summary from ' \
            'post where author_id = ? ORDER BY created DESC '
    params = (id,)
    ten_posts = db.execute(
        query, params
    ).fetchmany(10)
    return ten_posts


@bp.route('/<int:id>/info', methods=('GET', "POST"))
def info(id):
    user_info = get_info(id)
    posts = get_recent_ten_posts(id)
    return render_template('auth/info.html', info=user_info, posts=posts)


@bp.route('/<int:id>/update', methods=('GET', 'POST'))
def update(id):
    info = get_info(id)

    if request.method == 'POST':
        nick = request.form['nickname']
        addr = request.form['address']
        desc = request.form['description']

        db = get_db()
        db.execute(
            'UPDATE user SET nickname = ?, address = ?, description = ?'
            'WHERE id = ?',
            (nick, addr, desc, id)
        )
        db.commit()
        # return render_template('auth/info.html', info=info)
        return redirect(url_for('auth.info', id=info['id']))
    return render_template('auth/update.html', info=info)
