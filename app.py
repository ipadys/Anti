"""
Flask Backend для Roblox Friends Tool с Admin Panel
Запуск: python app.py
"""

from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_cors import CORS
import json
import uuid
import time
import threading
import hashlib
import os
from datetime import datetime
from functools import wraps

# Импортируем наш класс
from roblox_friends_tool import RobloxFriendsTool

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', str(uuid.uuid4()))
CORS(app)

# Файлы для хранения данных
KEYS_FILE = "api_keys.json"
USERS_FILE = "users.json"
JSON_FILE = "requests.json"
ADMIN_FILE = "admin.json"

# Глобальное хранилище
active_tools = {}
processing_status = {}

# ==================== УТИЛИТЫ ====================

def load_json_file(filename, default=None):
    """Загрузка JSON файла"""
    try:
        with open(filename, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return default if default is not None else {}

def save_json_file(filename, data):
    """Сохранение JSON файла"""
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def hash_password(password):
    """Хеширование пароля"""
    return hashlib.sha256(password.encode()).hexdigest()

def init_admin():
    """Инициализация админа"""
    if not os.path.exists(ADMIN_FILE):
        admin_data = {
            "username": "admin",
            "password": hash_password("admin123"),  # Поменяй после первого входа!
            "created_at": datetime.now().isoformat()
        }
        save_json_file(ADMIN_FILE, admin_data)
        print("✅ Admin created! Login: admin / Password: admin123")
        print("⚠️  CHANGE PASSWORD AFTER FIRST LOGIN!")

def init_files():
    """Инициализация всех файлов"""
    init_admin()
    
    if not os.path.exists(KEYS_FILE):
        save_json_file(KEYS_FILE, {})
    
    if not os.path.exists(USERS_FILE):
        save_json_file(USERS_FILE, {})
    
    if not os.path.exists(JSON_FILE):
        save_json_file(JSON_FILE, {"ids": []})

# ==================== ДЕКОРАТОРЫ ====================

def require_api_key(f):
    """Проверка API ключа"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key') or request.json.get('api_key')
        
        if not api_key:
            return jsonify({'success': False, 'error': 'API key required'}), 401
        
        keys = load_json_file(KEYS_FILE, {})
        if api_key not in keys:
            return jsonify({'success': False, 'error': 'Invalid API key'}), 403
        
        key_data = keys[api_key]
        if not key_data.get('active', True):
            return jsonify({'success': False, 'error': 'API key disabled'}), 403
        
        # Обновляем last_used
        key_data['last_used'] = datetime.now().isoformat()
        key_data['usage_count'] = key_data.get('usage_count', 0) + 1
        save_json_file(KEYS_FILE, keys)
        
        return f(*args, **kwargs)
    return decorated_function

def require_admin(f):
    """Проверка авторизации админа"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# ==================== МАРШРУТЫ - ГЛАВНАЯ ====================

@app.route('/')
def index():
    """Главная страница с проверкой ключа"""
    return render_template('index.html')

# ==================== МАРШРУТЫ - ADMIN ====================

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Страница входа в админку"""
    if request.method == 'GET':
        return render_template('admin_login.html')
    
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    admin = load_json_file(ADMIN_FILE)
    
    if username == admin['username'] and hash_password(password) == admin['password']:
        session['admin_logged_in'] = True
        return jsonify({'success': True})
    
    return jsonify({'success': False, 'error': 'Invalid credentials'}), 401

@app.route('/admin/logout')
def admin_logout():
    """Выход из админки"""
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin_login'))

@app.route('/admin')
@require_admin
def admin_panel():
    """Админ панель"""
    return render_template('admin.html')

@app.route('/admin/api/stats')
@require_admin
def admin_stats():
    """Статистика для админки"""
    keys = load_json_file(KEYS_FILE, {})
    users = load_json_file(USERS_FILE, {})
    json_data = load_json_file(JSON_FILE, {"ids": []})
    
    return jsonify({
        'success': True,
        'stats': {
            'total_keys': len(keys),
            'active_keys': sum(1 for k in keys.values() if k.get('active', True)),
            'total_users': len(users),
            'blocked_ids': len(json_data.get('ids', []))
        }
    })

@app.route('/admin/api/keys', methods=['GET'])
@require_admin
def get_keys():
    """Получить все ключи"""
    keys = load_json_file(KEYS_FILE, {})
    
    keys_list = []
    for key, data in keys.items():
        keys_list.append({
            'key': key,
            'name': data.get('name', 'Unknown'),
            'active': data.get('active', True),
            'created_at': data.get('created_at'),
            'last_used': data.get('last_used'),
            'usage_count': data.get('usage_count', 0)
        })
    
    return jsonify({'success': True, 'keys': keys_list})

@app.route('/admin/api/keys/create', methods=['POST'])
@require_admin
def create_key():
    """Создать новый ключ"""
    data = request.json
    name = data.get('name', 'Unnamed Key')
    
    new_key = str(uuid.uuid4())
    keys = load_json_file(KEYS_FILE, {})
    
    keys[new_key] = {
        'name': name,
        'active': True,
        'created_at': datetime.now().isoformat(),
        'last_used': None,
        'usage_count': 0
    }
    
    save_json_file(KEYS_FILE, keys)
    
    return jsonify({
        'success': True,
        'key': new_key,
        'message': f'Key created: {name}'
    })

@app.route('/admin/api/keys/toggle', methods=['POST'])
@require_admin
def toggle_key():
    """Включить/выключить ключ"""
    data = request.json
    key = data.get('key')
    
    keys = load_json_file(KEYS_FILE, {})
    
    if key not in keys:
        return jsonify({'success': False, 'error': 'Key not found'}), 404
    
    keys[key]['active'] = not keys[key].get('active', True)
    save_json_file(KEYS_FILE, keys)
    
    status = "enabled" if keys[key]['active'] else "disabled"
    return jsonify({'success': True, 'message': f'Key {status}'})

@app.route('/admin/api/keys/delete', methods=['POST'])
@require_admin
def delete_key():
    """Удалить ключ"""
    data = request.json
    key = data.get('key')
    
    keys = load_json_file(KEYS_FILE, {})
    
    if key not in keys:
        return jsonify({'success': False, 'error': 'Key not found'}), 404
    
    del keys[key]
    save_json_file(KEYS_FILE, keys)
    
    return jsonify({'success': True, 'message': 'Key deleted'})

@app.route('/admin/api/json/get')
@require_admin
def get_json_data():
    """Получить содержимое JSON"""
    json_data = load_json_file(JSON_FILE, {"ids": []})
    return jsonify({'success': True, 'data': json_data})

@app.route('/admin/api/json/update', methods=['POST'])
@require_admin
def update_json_data():
    """Обновить JSON"""
    data = request.json
    new_ids = data.get('ids', [])
    
    # Валидация - только числа
    try:
        new_ids = [int(id) for id in new_ids if str(id).strip()]
    except ValueError:
        return jsonify({'success': False, 'error': 'Invalid ID format'}), 400
    
    save_json_file(JSON_FILE, {"ids": new_ids})
    
    return jsonify({
        'success': True,
        'message': f'Updated {len(new_ids)} IDs',
        'count': len(new_ids)
    })

@app.route('/admin/api/json/add', methods=['POST'])
@require_admin
def add_json_ids():
    """Добавить ID в JSON"""
    data = request.json
    new_ids = data.get('ids', [])
    
    json_data = load_json_file(JSON_FILE, {"ids": []})
    current_ids = set(json_data.get('ids', []))
    
    # Добавляем новые ID
    try:
        for id in new_ids:
            current_ids.add(int(id))
    except ValueError:
        return jsonify({'success': False, 'error': 'Invalid ID format'}), 400
    
    save_json_file(JSON_FILE, {"ids": list(current_ids)})
    
    return jsonify({
        'success': True,
        'message': f'Added {len(new_ids)} IDs',
        'total': len(current_ids)
    })

@app.route('/admin/api/json/clear', methods=['POST'])
@require_admin
def clear_json():
    """Очистить JSON"""
    save_json_file(JSON_FILE, {"ids": []})
    return jsonify({'success': True, 'message': 'JSON cleared'})

@app.route('/admin/api/password/change', methods=['POST'])
@require_admin
def change_password():
    """Сменить пароль админа"""
    data = request.json
    old_password = data.get('old_password')
    new_password = data.get('new_password')
    
    admin = load_json_file(ADMIN_FILE)
    
    if hash_password(old_password) != admin['password']:
        return jsonify({'success': False, 'error': 'Wrong old password'}), 400
    
    admin['password'] = hash_password(new_password)
    save_json_file(ADMIN_FILE, admin)
    
    return jsonify({'success': True, 'message': 'Password changed'})

# ==================== API ДЛЯ ПОЛЬЗОВАТЕЛЕЙ ====================

@app.route('/api/connect', methods=['POST'])
@require_api_key
def connect():
    """Подключение к Roblox API"""
    try:
        data = request.json
        cookie = data.get('cookie', '').strip()
        tracker = data.get('tracker', '').strip() or None
        
        if not cookie:
            return jsonify({'success': False, 'error': 'Cookie is required'}), 400
        
        session_id = str(uuid.uuid4())
        tool = RobloxFriendsTool(cookie, tracker)
        active_tools[session_id] = tool
        
        return jsonify({
            'success': True,
            'session_id': session_id,
            'message': 'Successfully connected!'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/get-requests', methods=['POST'])
@require_api_key
def get_requests():
    """Получить количество заявок"""
    try:
        data = request.json
        session_id = data.get('session_id')
        
        if not session_id or session_id not in active_tools:
            return jsonify({'success': False, 'error': 'Invalid session'}), 400
        
        tool = active_tools[session_id]
        ids = tool.get_friend_requests()
        
        return jsonify({
            'success': True,
            'count': len(ids),
            'ids': ids
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/save-json', methods=['POST'])
@require_api_key
def save_json():
    """Сохранить ID в JSON (перезапись)"""
    try:
        data = request.json
        session_id = data.get('session_id')
        
        if not session_id or session_id not in active_tools:
            return jsonify({'success': False, 'error': 'Invalid session'}), 400
        
        tool = active_tools[session_id]
        tool.save_ids_to_json()
        
        return jsonify({
            'success': True,
            'message': 'IDs saved to requests.json'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/add-to-json', methods=['POST'])
@require_api_key
def add_to_json():
    """Добавить новые ID к существующим в JSON"""
    try:
        data = request.json
        session_id = data.get('session_id')
        
        if not session_id or session_id not in active_tools:
            return jsonify({'success': False, 'error': 'Invalid session'}), 400
        
        tool = active_tools[session_id]
        
        # Получаем текущие заявки
        new_ids = tool.get_friend_requests()
        
        # Загружаем существующие ID
        json_data = load_json_file(JSON_FILE, {"ids": []})
        existing_ids = set(json_data.get('ids', []))
        
        # Добавляем новые (без дубликатов)
        before_count = len(existing_ids)
        existing_ids.update(new_ids)
        after_count = len(existing_ids)
        
        # Сохраняем
        save_json_file(JSON_FILE, {"ids": list(existing_ids)})
        
        added_count = after_count - before_count
        
        return jsonify({
            'success': True,
            'message': f'Added {added_count} new IDs (total: {after_count})',
            'added': added_count,
            'total': after_count
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/accept-all', methods=['POST'])
@require_api_key
def accept_all():
    """Принять все заявки"""
    try:
        data = request.json
        session_id = data.get('session_id')
        
        if not session_id or session_id not in active_tools:
            return jsonify({'success': False, 'error': 'Invalid session'}), 400
        
        if session_id in processing_status and processing_status[session_id]['running']:
            return jsonify({'success': False, 'error': 'Already processing'}), 400
        
        processing_status[session_id] = {
            'running': True,
            'accepted': 0,
            'skipped': 0,
            'total': 0,
            'rps': 0.0,
            'logs': []
        }
        
        thread = threading.Thread(
            target=process_requests,
            args=(session_id,),
            daemon=True
        )
        thread.start()
        
        return jsonify({
            'success': True,
            'message': 'Processing started'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/status', methods=['POST'])
@require_api_key
def get_status():
    """Получить статус обработки"""
    try:
        data = request.json
        session_id = data.get('session_id')
        
        if session_id not in processing_status:
            return jsonify({
                'success': True,
                'running': False
            })
        
        status = processing_status[session_id]
        return jsonify({
            'success': True,
            'running': status['running'],
            'accepted': status['accepted'],
            'skipped': status['skipped'],
            'total': status['total'],
            'rps': status['rps'],
            'logs': status['logs'][-10:]
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

def process_requests(session_id):
    """Обработка заявок в фоновом режиме"""
    try:
        tool = active_tools[session_id]
        status = processing_status[session_id]
        
        try:
            with open(JSON_FILE, "r", encoding="utf-8") as f:
                ignored = set(json.load(f).get("ids", []))
        except FileNotFoundError:
            ignored = set()
        
        ids = tool.get_friend_requests()
        status['total'] = len(ids)
        status['logs'].append(f"Found {len(ids)} requests")
        
        start_time = time.time()
        last_update_time = start_time
        last_accepted_count = 0
        
        import concurrent.futures
        
        def worker(uid):
            if uid in ignored:
                return "skipped"
            return "accepted" if tool.accept_request(uid) else "failed"
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(worker, uid): uid for uid in ids}
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                
                if result == "accepted":
                    status['accepted'] += 1
                elif result == "skipped":
                    status['skipped'] += 1
                
                current_time = time.time()
                time_diff = current_time - last_update_time
                
                if time_diff >= 0.5:
                    accepted_diff = status['accepted'] - last_accepted_count
                    status['rps'] = accepted_diff / time_diff
                    last_update_time = current_time
                    last_accepted_count = status['accepted']
        
        total_time = time.time() - start_time
        avg_rps = status['accepted'] / total_time if total_time > 0 else 0
        status['rps'] = avg_rps
        status['logs'].append(f"Completed! Accepted: {status['accepted']}, Skipped: {status['skipped']}")
        status['logs'].append(f"Average speed: {avg_rps:.2f} req/s")
        
    except Exception as e:
        status['logs'].append(f"Error: {str(e)}")
    finally:
        status['running'] = False

# ==================== ЗАПУСК ====================

if __name__ == '__main__':
    print("="*60)
    print("🎮 ROBLOX FRIENDS TOOL - WEB SERVER")
    print("="*60)
    
    init_files()
    
    port = int(os.environ.get('PORT', 5000))
    
    print(f"\n🌐 Main: http://localhost:{port}")
    print(f"👑 Admin: http://localhost:{port}/admin")
    print("📝 Press CTRL+C to stop\n")
    
    app.run(debug=False, host='0.0.0.0', port=port)
