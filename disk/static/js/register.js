// ===== 密码实时校验 =====
function checkPassword() {
    const pwd = document.getElementById('password').value;
    const errorEl = document.getElementById('passwordError');
    const btn = document.getElementById('submitBtn');
    const rules = [
        { test: (v) => v.length >= 8, msg: '至少8位' },
        { test: (v) => /[A-Z]/.test(v), msg: '包含大写字母' },
        { test: (v) => /[a-z]/.test(v), msg: '包含小写字母' },
        { test: (v) => /[0-9]/.test(v), msg: '包含数字' },
        { test: (v) => /[!@#$%^&*(),.?":{}|<>]/.test(v), msg: '包含特殊字符' }
    ];

    if (pwd.length === 0) {
        errorEl.textContent = '';
        btn.disabled = false;
        return;
    }

    const failed = rules.filter(r => !r.test(pwd)).map(r => r.msg);
    
    if (failed.length > 0) {
        errorEl.textContent = '⚠️ 需：' + failed.join('、');
        errorEl.className = 'password-error';
        btn.disabled = true;
    } else {
        errorEl.textContent = '✅ 密码符合要求';
        errorEl.className = 'password-error success';
        btn.disabled = false;
    }
}