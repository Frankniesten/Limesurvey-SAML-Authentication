<?php

/*
 * LimeSurvey Auhtnetication Plugin for Limesurvey 3.14+
 * Auhtor: Frank Niesten
 * License: GNU General Public License v3.0
 * URL: https://github.com/Frankniesten/Limesurvey-SAML-Authentication
 * 
 * This plugin is based on the following LimeSurvey Plugins:
 * URL: https://github.com/LimeSurvey/LimeSurvey/blob/master/application/core/plugins/Authwebserver/Authwebserver.php
 * URL: https://github.com/LimeSurvey/LimeSurvey/blob/master/application/core/plugins/AuthLDAP/AuthLDAP.php
 * URL: https://github.com/pitbulk/limesurvey-saml
 *
 */

class AuthSAML extends LimeSurvey\PluginManager\AuthPluginBase
{
	protected $storage = 'DbStorage';
	protected $ssp = null;
	
	static protected $description = 'Core: SAML authentication';
    static protected $name = 'SAML';
    
    protected $settings = array(
        'simplesamlphp_path' => array(
            'type' => 'string',
            'label' => 'Path to the SimpleSAMLphp folder',
            'default' => '/var/www/simplesamlphp',
        ),
        'saml_authsource' => array(
            'type' => 'string',
            'label' => 'SAML authentication source',
            'default' => 'default-sp',
        ),
        'saml_uid_mapping' => array(
            'type' => 'string',
            'label' => 'SAML attributed used as username',
            'default' => 'uid',
        ),
        'saml_mail_mapping' => array(
            'type' => 'string',
            'label' => 'SAML attributed used as email',
            'default' => 'mail',
        ),
        'saml_name_mapping' => array(
            'type' => 'string',
            'label' => 'SAML attributed used as name',
            'default' => 'cn',
        ),
        'auto_update_users' => array(
            'type' => 'checkbox',
            'label' => 'Auto update users',
            'default' => true,
        ),
    );
    
    public function init() {
        
        $this->subscribe('getGlobalBasePermissions');
        $this->subscribe('beforeLogin');
        $this->subscribe('beforeLogout');
        $this->subscribe('newUserSession');
    }
    
    /**
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
    
    public function beforeLogin() {
	    
        $ssp = $this->get_saml_instance();
        $ssp->requireAuth();
        
        if ($ssp->isAuthenticated()) {
            $this->setAuthPlugin();
            $this->newUserSession();
        }
    }
	
    public function beforeLogout() {
        $ssp = $this->get_saml_instance();
        
        if ($ssp->isAuthenticated()) {
            $ssp->logout();
        }
    }
	
    public function newUserSession() {
		
        $ssp = $this->get_saml_instance();
        
        if ($ssp->isAuthenticated()) {
            
            $sUser = $this->getUserName();
            $name = $this->getUserCommonName();
            $mail = $this->getUserMail();

            $oUser = $this->api->getUserByName($sUser);
            
            if (is_null($oUser)) {
	            
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
	                Permission::model()->setGlobalPermission($oUser->uid, 'surveys', array('create_p'));
					
	                $oUser = $this->api->getUserByName($sUser);
	                $this->pluginManager->dispatchEvent(new PluginEvent('newUserLogin', $this));
	                $this->setAuthSuccess($oUser);
	                return;
        		}
    
            	else {
                	$this->setAuthFailure(self::ERROR_USERNAME_INVALID);
            	}	            
            }
            
            else {
		            
		        // *** Update user ***
                $auto_update_users = $this->get('auto_update_users', null, null, true);
                
                if ($auto_update_users) {
                    $changes = array (
                        'full_name' => $name, 
                        'email' => $mail,
                    );
                    
                    User::model()->updateByPk($oUser->uid, $changes);
                    $oUser = $this->api->getUserByName($sUser);
                }

		        $this->setAuthSuccess($oUser);     
	        }
        }
    }
 
    /**
     * Initialize SAML authentication
     * @return void
     */
    protected function get_saml_instance() {
        
        if ($this->ssp == null) {
            
            $simplesamlphp_path = $this->get('simplesamlphp_path', null, null, '/var/www/simplesamlphp');
            
            require_once($simplesamlphp_path.'/lib/_autoload.php');
            
            $saml_authsource = $this->get('saml_authsource', null, null, 'limesurvey');
            
            $this->ssp = new \SimpleSAML\Auth\Simple($saml_authsource);
	    }
        
        return $this->ssp;
    }
    
    /**
     * Get Userdata from SAML Attributes
     * @return void
     */
    public function getUserName() {
	    
        if ($this->_username == null) {
            $ssp = $this->get_saml_instance();
            $attributes = $this->ssp->getAttributes();
            if (!empty($attributes)) {
                $saml_uid_mapping = $this->get('saml_uid_mapping', null, null, 'uid');
                if (array_key_exists($saml_uid_mapping , $attributes) && !empty($attributes[$saml_uid_mapping])) {
                    $username = $attributes[$saml_uid_mapping][0];
                    $this->setUsername($username);
                }
            }
        }
        
        return $this->_username;
    }
    
    public function getUserCommonName() {
        
        $name = '';
        $ssp = $this->get_saml_instance();
        $attributes = $this->ssp->getAttributes();
        if (!empty($attributes)) {
            $saml_name_mapping = $this->get('saml_name_mapping', null, null, 'cn');
            if (array_key_exists($saml_name_mapping , $attributes) && !empty($attributes[$saml_name_mapping])) {
                $name = $attributes[$saml_name_mapping][0];
            }
        }
        
        return $name;
    }
    
    public function getUserMail() {
        
        $mail = '';
        $ssp = $this->get_saml_instance();
        $attributes = $this->ssp->getAttributes();
        if (!empty($attributes)) {
            $saml_mail_mapping = $this->get('saml_mail_mapping', null, null, 'mail');
            if (array_key_exists($saml_mail_mapping , $attributes) && !empty($attributes[$saml_mail_mapping])) {
                $mail = $attributes[$saml_mail_mapping][0];
            }
        }
        
        return $mail;
    }    
}
