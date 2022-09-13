<?php

namespace phpcms\model;

use pc_base;
use phpcms\libs\classes\model;

class admin_role_priv_model extends model
{
    public $table_name = '';

    function __construct()
    {
        $this->db_config = pc_base::load_config('database');
        $this->db_setting = 'default';
        $this->table_name = 'admin_role_priv';
        parent::__construct();
    }
}
