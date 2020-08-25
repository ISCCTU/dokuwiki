<?php

/**
 * DokuWiki Plugin authpdo (Auth Component)
 *
 * @license GPL 2 http://www.gnu.org/licenses/gpl-2.0.html
 * @author  Andreas Gohr <andi@splitbrain.org>
 */

// must be run within Dokuwiki
if (!defined('DOKU_INC')) die();

/**
 * Class auth_plugin_authpdo
 */
class auth_plugin_partakauth extends DokuWiki_Auth_Plugin
{
    /** @var PDO */
    protected $pdo;

    /** @var null|array The list of all groups */
    protected $groupcache = null;

    /**
     * Constructor.
     */
    public function __construct()
    {
        parent::__construct(); // for compatibility

        if (!class_exists('PDO')) {
            $this->debug('PDO extension for PHP not found.', -1, __LINE__);
            $this->success = false;
            return;
        }

        if (!$this->getConf('dsn')) {
            $this->debug('No DSN specified', -1, __LINE__);
            $this->success = false;
            return;
        }

        try {
            $this->pdo = new PDO(
                $this->getConf('dsn'),
                $this->getConf('user'),
                conf_decodeString($this->getConf('pass')),
                array(
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC, // always fetch as array
                    PDO::ATTR_EMULATE_PREPARES => true, // emulating prepares allows us to reuse param names
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, // we want exceptions, not error codes
                )
            );
        } catch (PDOException $e) {
            $this->debug($e);
            msg($this->getLang('connectfail'), -1);
            $this->success = false;
            return;
        }

        $this->cando['addUser'] = false;
        $this->cando['delUser'] = false;
        $this->cando['modLogin'] = false;
        $this->cando['modPass'] = false;
        $this->cando['modName'] = false;
        $this->cando['modMail'] = false;
        $this->cando['modGroups'] = false;
        $this->cando['getUsers'] = false;
        $this->cando['getUserCount'] = false;
        $this->cando['getGroups'] = true;

        $this->success = true;
    }

    /**
     * Check user+password
     *
     * @param   string $user the user name
     * @param   string $pass the clear text password
     * @return  bool
     */
    public function checkPass($user, $pass)
    {
        $result = $this->getUser($user);

        if ($result === false) {
            return false;
        }

        return password_verify(hash("sha512", $user . '@' . $pass), $result['password']);
    }

    /**
     * Return user info
     *
     * Returns info about the given user needs to contain
     * at least these fields:
     *
     * name string  full name of the user
     * mail string  email address of the user
     * grps array   list of groups the user is in
     *
     * @param   string $user the user name
     * @param   bool $requireGroups whether or not the returned data must include groups
     * @return array|bool containing user data or false
     */
    public function getUserData($user, $requireGroups = true)
    {
        $data = $this->getUser($user);

        if ($data == false) {
            return false;
        }

        $user = [
            'name' => "{$data['first_name']} {$data['last_name']}",
            'email' => $data['email']
        ];

        if ($requireGroups) {
            $groups = $this->query(
                "
                SELECT title FROM users_roles
                NATURAL JOIN roles
                WHERE id_user = :id_user
                ",
                ['id_user' => (int)$data['id_user']]
            );

            if ($groups === false) {
                return false;
            }

            $roleMap = [
                'supervisor' => 'admin',
                'admin' => 'admin',
                'partak' => 'user',
                'team' => 'team',
                'board' => 'board',
                'buddyManager' => 'coordinator',
                'integreatCoordinator' => 'coordinator',
            ];

            $userGroups = [];
            foreach ($groups as $group) {
                if (isset($roleMap[$group['title']]) && !isset($userGroups[$group['title']])) {
                    $userGroups[$group['title']] = $roleMap[$group['title']];
                }
            }

            $user['grps'] = array_values($userGroups);
        }

        return $user;
    }

    protected function getUser($email)
    {
        $data = $this->query(
            "SELECT users.*, people.* FROM users NATURAL JOIN people WHERE email = :email",
            ['email' => $email]
        );

        if (count($data) === 1) {
            return $data[0];
        }

        return false;
    }

    /**
     * Executes a query
     *
     * @param string $sql The SQL statement to execute
     * @param array $arguments Named parameters to be used in the statement
     * @return array|int|bool The result as associative array for SELECTs, affected rows for others, false on error
     */
    protected function query($sql, $arguments = array())
    {
        $sql = trim($sql);

        if (empty($sql)) {
            $this->debug('No SQL query given', -1, __LINE__);
            return false;
        }

        // execute
        $params = array();
        $sth = $this->pdo->prepare($sql);
        try {
            // prepare parameters - we only use those that exist in the SQL
            foreach ($arguments as $key => $value) {
                if (is_array($value) || is_object($value)) {
                    continue;
                }

                if ($key[0] != ':') {
                    $key = ":$key"; // prefix with colon if needed
                }

                if (strpos($sql, $key) === false) {
                    continue; // skip if parameter is missing
                }

                if (is_int($value)) {
                    $sth->bindValue($key, $value, PDO::PARAM_INT);
                } else {
                    $sth->bindValue($key, $value);
                }

                $params[$key] = $value; //remember for debugging
            }

            $sth->execute();
            if (strtolower(substr($sql, 0, 6)) == 'select') {
                $result = $sth->fetchAll();
            } else {
                $result = $sth->rowCount();
            }
        } catch (Exception $e) {
            // report the caller's line
            $trace = debug_backtrace();
            $line = $trace[0]['line'];
            $dsql = $this->debugSQL($sql, $params, !defined('DOKU_UNITTEST'));
            $this->debug($e, -1, $line);
            $this->debug("SQL: <pre>$dsql</pre>", -1, $line);
            $result = false;
        }
        $sth->closeCursor();
        $sth = null;

        return $result;
    }

    /**
     * Wrapper around msg() but outputs only when debug is enabled
     *
     * @param string|Exception $message
     * @param int $err
     * @param int $line
     */
    protected function debug($message, $err = 0, $line = 0)
    {
        if (!$this->getConf('debug')) {
            return;
        }

        if (is_a($message, 'Exception')) {
            $err = -1;
            $msg = $message->getMessage();
            if (!$line) {
                $line = $message->getLine();
            }
        } else {
            $msg = $message;
        }

        if (defined('DOKU_UNITTEST')) {
            printf("\n%s, %s:%d\n", $msg, __FILE__, $line);
        } else {
            msg('partakauth: ' . $msg, $err, $line, __FILE__);
        }
    }

    /**
     * create an approximation of the SQL string with parameters replaced
     *
     * @param string $sql
     * @param array $params
     * @param bool $htmlescape Should the result be escaped for output in HTML?
     * @return string
     */
    protected function debugSQL($sql, $params, $htmlescape = true)
    {
        foreach ($params as $key => $val) {
            if (is_int($val)) {
                $val = $this->pdo->quote($val, PDO::PARAM_INT);
            } elseif (is_bool($val)) {
                $val = $this->pdo->quote($val, PDO::PARAM_BOOL);
            } elseif (is_null($val)) {
                $val = 'NULL';
            } else {
                $val = $this->pdo->quote($val);
            }
            $sql = str_replace($key, $val, $sql);
        }

        if ($htmlescape) {
            $sql = hsc($sql);
        }

        return $sql;
    }
}
