<?php
/**
 * Oauth Controller 抽象層
 */

namespace LittleChou\CiOauth2;


use OAuth2\GrantType\ClientCredentials;
use OAuth2\GrantType\RefreshToken;
use OAuth2\Request;
use OAuth2\Response;
use OAuth2\Server;
use OAuth2\Storage\Pdo;
use Restserver\Libraries\REST_Controller;

abstract class Controller extends REST_Controller
{

    /**
     * @var Server
     */
    protected $oAuthServer;

    /**
     * @var Pdo
     */
    protected $oAuthStorage;

    /**
     * @var array
     */
    private $ignoreMethods = [];


    public function __construct($config = 'rest')
    {
        parent::__construct($config);
        $this->load->database();
        $this->initOauth();
        $this->middleware();
    }

    /**
     * Oauth 初始化
     */
    private function initOauth()
    {
        $tableList = $this->db->list_tables();
        if (!in_array('oauth_clients', $tableList)) {
            $sqlFilePath = dirname(__FILE__) . "/../sql/sql-general.sql";
            $sql = file_get_contents($sqlFilePath);
            $sqlQuery = explode(';', $sql);
            foreach ($sqlQuery as $queryString) {
                $this->db->query(trim($queryString));
            }
        }
        if (!empty($this->db->dsn)) {
            $this->oAuthStorage = new Pdo(['dsn' => $this->db->dsn, 'username' => $this->db->username, 'password' => $this->db->password]);
        } else {
            $dbConn = 'mysql:host=' . $this->db->hostname . ';dbname=' . $this->db->database;
            $this->oAuthStorage = new Pdo(['dsn' => $dbConn, 'username' => $this->db->username, 'password' => $this->db->password]);
        }
        $this->oAuthServer = new Server($this->oAuthStorage);
        $grandType = new RefreshToken($this->oAuthStorage,[
            'always_issue_new_refresh_token' => true
        ]);
        $this->oAuthServer->addGrantType($grandType);
        $this->oAuthServer->addGrantType(new ClientCredentials($this->oAuthStorage));
    }

    /**
     * 中介層 oauth service 檢查
     */
    private function middleware()
    {
        $methodName = $this->router->method;
        $enableValidate = true;
        // 白名單 檢查
        if (count($this->ignoreMethods) >= 1) {
            if (in_array($methodName, $this->ignoreMethods)) {
                $enableValidate = false;
            }
        }
        if ($enableValidate) {
            if (!$this->oAuthServer->verifyResourceRequest(Request::createFromGlobals())) {
                $this->oAuthServer->getResponse()->send();
                die();
            }
        }
    }

    /**
     * 新增不檢查的 Method Name
     * @param $method
     * @return $this
     */
    public function addIgnoreMethod($method)
    {
        if (!in_array($method, $this->ignoreMethods)) {
            $this->ignoreMethods[] = $method;
        }
        return $this;
    }

    /**
     * 發送 Oauth Token
     * @param bool $isAuth
     * @param null $userId
     */
    protected function sendOauthToken($isAuth = false, $userId = null)
    {
        $this->oAuthServer->handleAuthorizeRequest(
            Request::createFromGlobals(),
            new Response(),
            $isAuth,
            $userId);
        $this->oAuthServer->handleTokenRequest(Request::createFromGlobals(), new Response())->send();
    }

}