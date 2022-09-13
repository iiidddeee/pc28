<?php

namespace phpcms\modules\admin;

use pc_base;
use phpcms\libs\classes\model;
use phpcms\libs\classes\param;
use phpcms\model\admin_model;
use phpcms\model\times_model;
use phpcms\modules\admin\classes\admin;

/**
 * Class index
 * @property model $db
 * @property model $times_db
 */
class index extends admin
{

    public function __construct()
    {
        parent::__construct();
        $this->db = new admin_model();
        $_SESSION['lock_screen'] = 0;
    }

    public function init()
    {
        $userid = $_SESSION['userid'];
        $admin_username = param::get_cookie('admin_username');
        $roles = getcache('role', 'commons');
        $rolename = $roles[$_SESSION['roleid']];
        include $this->admin_tpl('index');
    }

    public function login()
    {
        if (isset($_GET['dosubmit'])) {
            //不为口令卡验证
            $username = isset($_POST['username']) ? trim($_POST['username']) : showmessage(L('nameerror'), HTTP_REFERER);
            $code = isset($_POST['code']) && trim($_POST['code']) ? trim($_POST['code']) : showmessage(L('input_code'), HTTP_REFERER);
            if ($_SESSION['code'] != strtolower($code)) {
                $_SESSION['code'] = '';
                showmessage(L('code_error'), HTTP_REFERER);
            }
            $_SESSION['code'] = '';
            
            if (!is_username($username)) {
                showmessage(L('username_illegal'), HTTP_REFERER);
            }
            //密码错误剩余重试次数
            $this->times_db = new times_model();
            $rtime = $this->times_db->get_one(['username' => $username, 'isadmin' => 1]);
            $maxloginfailedtimes = getcache('common', 'commons');
            $maxloginfailedtimes = (int)$maxloginfailedtimes['maxloginfailedtimes'];

            if ($rtime['times'] >= $maxloginfailedtimes) {
                $minute = 60 - floor((SYS_TIME - $rtime['logintime']) / 60);
                if ($minute > 0) {
                    showmessage(L('wait_1_hour', ['minute' => $minute]));
                }
            }
            //查询帐号
            $r = $this->db->get_one(['username' => $username]);
            if (!$r) {
                showmessage(L('user_not_exist'), '?m=admin&c=index&a=login');
            }
            $password = md5(md5(trim((!isset($_GET['card']) ? $_POST['password'] : $_SESSION['card_password']))) . $r['encrypt']);

            if ($r['password'] != $password) {
                $ip = ip();
                if ($rtime && $rtime['times'] < $maxloginfailedtimes) {
                    $times = $maxloginfailedtimes - intval($rtime['times']);
                    $this->times_db->update(['ip' => $ip, 'isadmin' => 1, 'times' => '+=1'], ['username' => $username]);
                } else {
                    $this->times_db->delete(['username' => $username, 'isadmin' => 1]);
                    $this->times_db->insert(['username' => $username, 'ip' => $ip, 'isadmin' => 1, 'logintime' => SYS_TIME, 'times' => 1]);
                    $times = $maxloginfailedtimes;
                }
                showmessage(L('password_error', ['times' => $times]), '?m=admin&c=index&a=login', 3000);
            }
            $this->times_db->delete(['username' => $username]);

            $this->db->update(['lastloginip' => ip(), 'lastlogintime' => SYS_TIME], ['userid' => $r['userid']]);
            $_SESSION['userid'] = $r['userid'];
            $_SESSION['roleid'] = $r['roleid'];
            $_SESSION['pc_hash'] = random(6, 'abcdefghigklmnopqrstuvwxwyABCDEFGHIGKLMNOPQRSTUVWXWY0123456789');
            $cookie_time = SYS_TIME + 86400 * 30;
            if (!$r['lang']) {
                $r['lang'] = 'zh-cn';
            }
            param::set_cookie('admin_username', $username, $cookie_time);
            param::set_cookie('userid', $r['userid'], $cookie_time);
            param::set_cookie('sys_lang', $r['lang'], $cookie_time);
            showmessage(L('login_success'), '?m=admin&c=index');
        } else {
            pc_base::load_sys_class('form', '', 0);
            include $this->admin_tpl('login');
        }
    }

    public function public_logout() {
        $_SESSION['userid'] = 0;
        $_SESSION['roleid'] = 0;
        param::set_cookie('admin_username','');
        param::set_cookie('userid',0);
        showmessage(L('logout_success').$phpsso_logout,'?m=admin&c=index&a=login');
    }

    public function public_main()
    {
        pc_base::load_app_func('global');
        pc_base::load_app_func('admin');
        define('PC_RELEASE', pc_base::load_config('version', 'pc_release'));

        $admin_username = param::get_cookie('admin_username');
        $roles = getcache('role', 'commons');
        $userid = $_SESSION['userid'];
        $rolename = $roles[$_SESSION['roleid']];
        $r = $this->db->get_one(['userid' => $userid]);
        $logintime = $r['lastlogintime'];
        $loginip = $r['lastloginip'];
        $sysinfo = get_sysinfo();
        $sysinfo['mysqlv'] = $this->db->version();
        $show_header = $show_pc_hash = 1;
        /*检测框架目录可写性*/
        $pc_writeable = is_writable(PATH_PHPCMS . 'base.php');
        $common_cache = getcache('common', 'commons');
        $logsize_warning = errorlog_size() > $common_cache['errorlog_size'] ? '1' : '0';
        $adminpanel = $this->panel_db->select(['userid' => $userid], '*', 20, 'datetime');
        $product_copyright = '酷溜网(北京)科技有限公司';
        $programmer = '马玉辉、张明雪、李天会、潘兆志';
        $designer = '张二强';
        ob_start();
        include $this->admin_tpl('main');
        $data = ob_get_contents();
        ob_end_clean();
        system_information($data);
    }

    /**
     * 维持 session 登陆状态
     */
    public function public_session_life()
    {
        $userid = $_SESSION['userid'];

        return true;
    }



}
