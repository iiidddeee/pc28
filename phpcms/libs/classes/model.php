<?php

namespace phpcms\libs\classes;

/**
 * 数据模型基类
 * @property $pages string
 */
class model
{
    //数据库配置
    protected $db_config = [];
    //数据库连接
    protected $db = '';
    //调用数据库的配置项
    protected $db_setting = 'default';
    //数据表名
    protected $table_name = '';
    //表前缀
    public $db_tablepre = '';

    public function __construct()
    {
        if (!isset($this->db_config[$this->db_setting])) {
            $this->db_setting = 'default';
        }
        $this->table_name = $this->db_config[$this->db_setting]['tablepre'] . $this->table_name;
        $this->db_tablepre = $this->db_config[$this->db_setting]['tablepre'];
        $this->db = db_factory::get_instance($this->db_config)->get_database($this->db_setting);
    }

    /**
     * 执行sql查询
     * @param string     $where 查询条件[例`name`='$name']
     * @param string     $data 需要查询的字段值[例`name`,`gender`,`birthday`]
     * @param int|string $limit 返回结果范围[例：10或10,10 默认为空]
     * @param string     $order 排序方式    [默认按数据库默认方式排序]
     * @param string     $group 分组方式    [默认为空]
     * @param string     $key 返回数组按键名排序
     * @return array        查询结果集数组
     */
    final public function select($where = '', $data = '*', $limit = '', $order = '', $group = '', $key = '')
    {
        if (is_array($where)) {
            $where = $this->sqls($where);
        }

        return $this->db->select($data, $this->table_name, $where, $limit, $order, $group, $key);
    }

    /**
     * 查询多条数据并分页
     * @param $where
     * @param $order
     * @param $page
     * @param $pagesize
     * @return mixed
     */
    final public function listinfo($where = '', $order = '', $page = 1, $pagesize = 20, $key = '', $setpages = 10, $urlrule = '', $array = [], $data = '*')
    {
        $where = to_sqls($where);
        $this->number = $this->count($where);
        $page = max(intval($page), 1);
        $offset = $pagesize * ($page - 1);
        $this->pages = pages($this->number, $page, $pagesize, $urlrule, $array, $setpages);
        $array = [];
        if ($this->number > 0) {
            return $this->select($where, $data, "$offset, $pagesize", $order, '', $key);
        } else {
            return [];
        }
    }

    /**
     * 获取单条记录查询
     * @param string       $where 查询条件
     * @param array|string $data 需要查询的字段值[例`name`,`gender`,`birthday`]
     * @param string       $order 排序方式    [默认按数据库默认方式排序]
     * @param string       $group 分组方式    [默认为空]
     * @return array/null    数据查询结果集,如果不存在，则返回空
     */
    final public function get_one($where = '', $data = '*', $order = '', $group = '')
    {
        if (is_array($where)) {
            $where = $this->sqls($where);
        }

        return $this->db->get_one($data, $this->table_name, $where, $order, $group);
    }

    /**
     * 直接执行sql查询
     * @param string $sql 查询sql语句
     * @return boolean|model 如果为查询语句，返回资源句柄，否则返回true/false
     */
    final public function query($sql)
    {
        $sql = str_replace('phpcms_', $this->db_tablepre, $sql);

        return $this->db->query($sql);
    }

    /**
     * 执行添加记录操作
     * @param array $data 要增加的数据，参数为数组。数组key为字段值，数组值为数据取值
     * @param bool  $return_insert_id 是否返回新建ID号
     * @param bool  $replace 是否采用 replace into的方式添加数据
     * @return boolean
     */
    final public function insert($data, $return_insert_id = false, $replace = false)
    {
        return $this->db->insert($data, $this->table_name, $return_insert_id, $replace);
    }

    /**
     * 获取最后一次添加记录的主键号
     * @return int
     */
    final public function insert_id()
    {
        return $this->db->insert_id();
    }

    /**
     * 执行更新记录操作
     * @param array  $data 要更新的数据内容，参数可以为数组也可以为字符串，建议数组。
     *                        为数组时数组key为字段值，数组值为数据取值
     *                        为字符串时[例：`name`='phpcms',`hits`=`hits`+1]。
     *                        为数组时[例: array('name'=>'phpcms','password'=>'123456')]
     *                        数组的另一种使用array('name'=>'+=1', 'base'=>'-=1');程序会自动解析为`name` = `name` + 1, `base` = `base` - 1
     * @param string $where 更新数据时的条件,可为数组或字符串
     * @return boolean
     */
    final public function update($data, $where = '')
    {
        if (is_array($where)) {
            $where = $this->sqls($where);
        }

        return $this->db->update($data, $this->table_name, $where);
    }

    /**
     * 执行删除记录操作
     * @param string|array $where 删除数据条件,不充许为空。
     * @return boolean
     */
    final public function delete($where)
    {
        if (is_array($where)) {
            $where = $this->sqls($where);
        }

        return $this->db->delete($this->table_name, $where);
    }

    /**
     * 计算记录数
     * @param string|array $where 查询条件
     * @return int
     */
    final public function count($where = '')
    {
        $r = $this->get_one($where, "COUNT(*) AS num");

        return $r['num'];
    }

    /**
     * 将数组转换为SQL语句
     * @param string|array $where 要生成的数组
     * @param string       $font 连接串。
     * @return string
     */
    final public function sqls($where, $font = ' AND ')
    {
        if (is_array($where)) {
            $sql = '';
            foreach ($where as $key => $val) {
                $sql .= $sql ? " $font `$key` = '$val' " : " `$key` = '$val'";
            }

            return $sql;
        } else {
            return $where;
        }
    }

    /**
     * 获取最后数据库操作影响到的条数
     * @return int
     */
    final public function affected_rows()
    {
        return $this->db->affected_rows();
    }

    /**
     * 获取数据表主键
     * @return array
     */
    final public function get_primary()
    {
        return $this->db->get_primary($this->table_name);
    }

    /**
     * 获取表字段
     * @param string $table_name 表名
     * @return array
     */
    final public function get_fields($table_name = '')
    {
        if (empty($table_name)) {
            $table_name = $this->table_name;
        } else {
            $table_name = $this->db_tablepre . $table_name;
        }

        return $this->db->get_fields($table_name);
    }

    /**
     * 检查表是否存在
     * @param string $table 表名
     * @return boolean
     */
    final public function table_exists($table)
    {
        return $this->db->table_exists($this->db_tablepre . $table);
    }

    /**
     * 检查字段是否存在
     * @paramstring $field 字段名
     * @return boolean
     */
    public function field_exists($field)
    {
        $fields = $this->db->get_fields($this->table_name);

        return array_key_exists($field, $fields);
    }

    final public function list_tables()
    {
        return $this->db->list_tables();
    }

    /**
     * 返回数据结果集
     */
    final public function fetch_array()
    {
        $data = [];
        while ($r = $this->db->fetch_next()) {
            $data[] = $r;
        }

        return $data;
    }

    /**
     * 返回数据库版本号
     */
    final public function version()
    {
        return $this->db->version();
    }
}