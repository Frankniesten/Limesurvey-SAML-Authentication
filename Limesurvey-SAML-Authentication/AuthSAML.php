<?php

/*
 * LimeSurvey Auhtnetication Plugin for Limesurvey 3.14+
 * Auhtor: Frank Niesten
 * License: GNU General Public License v3.0
 *
 * This plugin is based on the following LimeSurvey Plugins:
 * URL: https://github.com/LimeSurvey/LimeSurvey/blob/master/application/core/plugins/Authwebserver/Authwebserver.php
 * URL: https://github.com/LimeSurvey/LimeSurvey/blob/master/application/core/plugins/AuthLDAP/AuthLDAP.php
 * URL: https://github.com/pitbulk/limesurvey-saml
 * URL: https://github.com/Frankniesten/Limesurvey-SAML-Authentication
 */

use SimpleSAML\Auth\Simple;

class AuthSAML extends LimeSurvey\PluginManager\AuthPluginBase
{
    protected $storage = 'DbStorage';
    protected $ssp = null;

    static protected $description = 'Core: SAML authentication';
    static protected $name = 'SAML';

    /**
     * @var array
     */
    protected $settings = array(
        'simplesamlphp_path' => array(
            'type' => 'string',
            'label' => 'Path to the SimpleSAMLphp folder',
            'default' => '/usr/share/simplesamlphp',
        ),
        'simplesamlphp_cookie_session_storage' => array(
            'type' => 'checkbox',
            'label' => 'Does simplesamlphp use cookie as a session storage ?',
            'default' => true,
        ),
        'saml_authsource' => array(
            'type' => 'string',
            'label' => 'SAML authentication source',
            'default' => 'default-sp',
        ),
        'saml_uid_mapping' => array(
            'type' => 'string',
            'label' => 'SAML attribute used as username',
            'default' => 'uid',
        ),
        'saml_mail_mapping' => array(
            'type' => 'string',
            'label' => 'SAML attribute used as email',
            'default' => 'mail',
        ),
        'saml_name_mapping' => array(
            'type' => 'string',
            'label' => 'SAML attribute used as name',
            'default' => 'cn',
        ),
        'auto_create_users' => array(
            'type' => 'checkbox',
            'label' => 'Auto create users',
            'default' => true,
        ),
        'auto_update_users' => array(
            'type' => 'checkbox',
            'label' => 'Auto update users',
            'default' => true,
        ),
        'force_saml_login' => array(
            'type' => 'checkbox',
            'label' => 'Force SAML login.',
            'default' => false,
        ),
        'authtype_base' => array(
            'type' => 'string',
            'label' => 'Authtype base',
            'default' => 'Authdb',
        ),
        'storage_base' => array(
            'type' => 'string',
            'label' => 'Storage base',
            'default' => 'DbStorage',
        ),
        'logout_redirect' => array(
            'type' => 'string',
            'label' => 'Logout Redirect URL',
            'default' => '/admin',
        ),
    );

    /**
     * init
     */
    public function init()
    {
        $this->storage = $this->get('storage_base', null, null, 'DbStorage');

        $this->subscribe('getGlobalBasePermissions');
        $this->subscribe('beforeLogin');
        $this->subscribe('newUserSession');
        $this->subscribe('afterLogout');

        if (!$this->get('force_saml_login', null, null, false)) {
            $this->subscribe('newLoginForm');
        }
    }

    /**
     * getGlobalBasePermissions
     *
     * Add AuthLDAP Permission to global Permission
     */
    public function getGlobalBasePermissions()
    {
        $this->getEvent()->append('globalBasePermissions', array(
            'auth_saml' => array(
                'create' => false,
                'update' => false,
                'delete' => false,
                'import' => false,
                'export' => false,
                'title' => gT("Use SAML authentication"),
                'description' => gT("Use SAML authentication"),
                'img' => 'usergroup'
            ),
        ));
    }

    /**
     * beforeLogin
     */
    public function beforeLogin()
    {
        if ($this->get('force_saml_login', null, null, false)) {
            $this->getSAMLInstance()->requireAuth();
        }

        if ($this->getSAMLInstance()->isAuthenticated()) {
            $this->setAuthPlugin();
            $this->newUserSession();
        }
    }

    /**
     * afterLogout
     */
    public function afterLogout()
    {
        $redirect = $this->get('logout_redirect', null, null, '/admin');

        if ($this->getSAMLInstance()->isAuthenticated()) {
            Yii::app()->controller->redirect($this->getSAMLInstance()->getLogoutUrl($redirect));
            Yii::app()->end();
        }
    }

    /**
     * newLoginForm
     */
    public function newLoginForm()
    {
        $authTypeBase = $this->get('authtype_base', null, null, 'Authdb');

        $loginFormContent = '<div style="text-align:center; padding-bottom: 10px; margin-bottom: 10px; border-bottom: dashed 1px #000;">Click on that button to initiate SAML Login<br><a href="'.$this->getSAMLInstance()->getLoginURL().'" title="SAML Login"><img height="60" src="'.Yii::app()->getConfig('imageurl').'/saml_logo.png"></a></><br></div>';

        $this
            ->getEvent()
            ->getContent($authTypeBase)
            ->addContent($loginFormContent, 'prepend');
    }

    /**
     * newUserSession
     */
    public function newUserSession()
    {
        if ($this->getSAMLInstance()->isAuthenticated()) {
            $sUser = $this->getUserName();
            $name = $this->getUserCommonName();
            $mail = $this->getUserMail();

            $oUser = $this->api->getUserByName($sUser);

            $auto_create_users = $this->get('auto_create_users', null, null, true);

            if (is_null($oUser) and $auto_create_users) {

                // Create new user
                $oUser = new User;
                $oUser->users_name = $sUser;
                $oUser->setPassword(createPassword());
                $oUser->full_name = $name;
                $oUser->parent_id = 1;
                $oUser->email = $mail;

                if ($oUser->save()) {
                    $permission = new Permission;

                    Permission::model()->setGlobalPermission($oUser->uid, 'auth_saml');

                    $oUser = $this->api->getUserByName($sUser);

                    $this->pluginManager->dispatchEvent(new PluginEvent('newUserLogin', $this));

                    $this->setAuthSuccess($oUser);
                } else {
                    $this->setAuthFailure(self::ERROR_USERNAME_INVALID);
                }
            } elseif (is_null($oUser)) {
                throw new CHttpException(401, gT("We are sorry but you do not have an account."));
            } else {
                // *** Update user ***
                $auto_update_users = $this->get('auto_update_users', null, null, true);

                if ($auto_update_users) {
                    /**
                     * Added 'users_name' => $sUser
                     * to prevent getting stuck in redirect loop when
                     * there is a difference in case between existing username
                     * and the username coming from SAML
                     */
                    $changes = array (
                        'users_name' => $sUser,
                        'full_name' => $name,
                        'email' => $mail,
                    );

                    User::model()->updateByPk($oUser->uid, $changes);
                    $oUser = $this->api->getUserByName($sUser);
                }

                $this->setAuthSuccess($oUser);
            }
        }
        $flag = $this->get('simplesamlphp_cookie_session_storage', null, null, true);

        if ($flag){
            $session = SimpleSAML_Session::getSessionFromRequest();
            $session->cleanup();
        }
    }

    /**
     * getSAMLInstance
     *
     * Initialize SAML authentication
     * @return Simple
     */
    public function getSAMLInstance()
    {
        if ($this->ssp == null) {
            $simpleSAMLPath = $this->get('simplesamlphp_path', null, null, '/var/www/simplesamlphp');
            require_once($simpleSAMLPath.'/lib/_autoload.php');

            $samlAuthSource = $this->get('saml_authsource', null, null, 'limesurvey');
            $this->ssp = new Simple($samlAuthSource);
        }

        return $this->ssp;
    }

    /**
     * getUserName
     *
     * Get Userdata from SAML Attributes
     * @return void
     */
    public function getUserName()
    {
        if ($this->_username == null) {
            $username = $this->getUserNameAttribute();

            if ($username !== false) {
                $this->setUsername($username);
            }
        }

        return $this->_username;
    }

    /**
     * getUserNameAttribute
     *
     * @return false
     */
    public function getUserNameAttribute()
    {
        $attributes = $this->getSAMLInstance()->getAttributes();

        if (!empty($attributes)) {
            $saml_uid_mapping = $this->get('saml_uid_mapping', null, null, 'uid');

            if (array_key_exists($saml_uid_mapping, $attributes) && !empty($attributes[$saml_uid_mapping])) {
                return $attributes[$saml_uid_mapping][0];
            }
        }

        return false;
    }

    /**
     * getUserCommonName
     *
     * @return string
     */
    public function getUserCommonName()
    {
        $name = '';
        $attributes = $this->getSAMLInstance()->getAttributes();

        if (!empty($attributes)) {
            $saml_name_mapping = $this->get('saml_name_mapping', null, null, 'cn');

            if (array_key_exists($saml_name_mapping , $attributes) && !empty($attributes[$saml_name_mapping])) {
                $name = $attributes[$saml_name_mapping][0];
            }
        }

        return $name;
    }

    /**
     * getUserMail
     *
     * @return string
     */
    public function getUserMail()
    {
        $mail = '';
        $attributes = $this->getSAMLInstance()->getAttributes();

        if (!empty($attributes)) {
            $saml_mail_mapping = $this->get('saml_mail_mapping', null, null, 'mail');

            if (array_key_exists($saml_mail_mapping , $attributes) && !empty($attributes[$saml_mail_mapping])) {
                $mail = $attributes[$saml_mail_mapping][0];
            }
        }

        return $mail;
    }
}
