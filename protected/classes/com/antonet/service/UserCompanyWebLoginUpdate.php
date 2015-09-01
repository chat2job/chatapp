<?php
	class UserCompanyWebLoginUpdate extends AppService {
	
		/**
		 * Default Constructor
		 */
		public function __construct($data) {
			parent::__construct($data);
		}
	
		/**
		 * Default Destructor
		 */
		public function __destruct() {
	
		}
	
		/**
		 * Perform the web service
		 *
		 */
		public function perform() {
			Logger::trace(__CLASS__.' perform');
			
			$response           = '';
			$userId          = $this->json['userId'];
			$currentPassword    ='';
			if(isset($this->json['webLogin']['currentPassword'])){
				$currentPassword = $this->json['webLogin']['currentPassword'];
			}
			$newPassword 		='';
			if(isset($this->json['webLogin']['newPassword'])){
				$newPassword   		= $this->json['webLogin']['newPassword'];
			}

			$BOOT = BootStrip::getInstance();
			$BOOT->addLibrary('DAOApplicationUser');
			$BOOT->addLibrary('DBOUserCompanyProfile');
			$BOOT->addLibrary('DAOUserCompanyProfile');
			$BOOT->addLibrary('DBOWebLogin');
			$BOOT->addLibrary('DAOWebLogin');
			$BOOT->addLibrary('DBOWebLoginStatus');
			$BOOT->addLibrary('HashSecure');
			$BOOT->addLibrary('DAOWebAccess');
			$BOOT->addLibrary('DAOWebChatMessageNotify');
			$BOOT->addLibrary('DBOAccountType');
			$BOOT->loadLibrary(PATH_CLASS);
			
			$mysql = $BOOT->getDBConnector();
				
			$daoApplicationUser = new DAOApplicationUser('ApplicationUser', $mysql);
			$dboApplicationUser = $daoApplicationUser->getUserByUserId($userId);
				
			if ($dboApplicationUser == null) {
				$this->response   = '';
				$this->statusCode = RETCODE_ERR_MISSING_CMY;
			} else if ($dboApplicationUser->getUserType_userTypeCode() != DBOUserType::$USERTYPE_COMPANY) {
				$this->response   = '';
				$this->statusCode = RETCODE_ERR_MISSING_CMY;
				Logger::trace('ApplicationUser invalid userType '.$dboApplicationUser->getUserType_userTypeCode().' not found');
			} else if($newPassword==''){
				$this->statusCode = RETCODE_ERR_WEBPASSWORD_INCORR;	
				Logger::trace('New Password not set');
			} else {
				$this->response   = '';
				$this->statusCode = RETCODE_OK;
				
				$daoUserCompanyProfile = new DAOUserCompanyProfile('UserCompanyProfile', $mysql);
				$dboUserCompanyProfile = $daoUserCompanyProfile->getByUserId($dboApplicationUser->getUserId());
				
				// update seeker profile
				if ($dboUserCompanyProfile == null) {
					$this->response   = '';
					$this->statusCode = RETCODE_ERR_MISSING_CMY;
				}else{
					$daoWebLogin = new DAOWebLogin('WebLogin', $mysql);
					$webLogins= $daoWebLogin->getByUserId($dboApplicationUser->getUserId());
					
					if(sizeof($webLogins)==0){
						$dboWebLogin = new DBOWebLogin();
						$dboWebLogin->setApplicationUser_userId($dboApplicationUser->getUserId());
						//todo current auto process, later open to multi email account??
						$dboWebLogin->setWebLoginName($dboApplicationUser->getUserEmail());
						$dboWebLogin->setWebPassword(HashSecure::create_hash($newPassword));
						$dboWebLogin->setWebLoginStatus_statusCode(DBOWebLoginStatus::$STATUS_ACTIVE);
						$dboWebLogin->setAccountType_typeCode(DBOAccountType::$OWNER);
						$daoWebLogin->addToCollector($dboWebLogin);
						$daoWebLogin->insert();
					}else{
						$dboWebLogin = $webLogins[0];
						if(!HashSecure::validate_password($currentPassword, $dboWebLogin->getWebPassword())){
							$this->response   = '';
							$this->statusCode = RETCODE_ERR_WEBPASSWORD_INCORR;
						}else{
							$dboWebLogin->setWebPassword(HashSecure::create_hash($newPassword));
							$daoWebLogin->addToCollector($dboWebLogin);
							$daoWebLogin->update();
							
							/**Revoke all WebAccess**/
							$daoWebAccess = new DAOWebAccess('WebAccess', $mysql);
							$accesses = $daoWebAccess->getAccessesByLoginId($dboWebLogin->getWebLoginId());
							
							$daoWebChatMessageNotify = new DAOWebChatMessageNotify('WebChatMessageNotify',$mysql);
							
							foreach($accesses as $dboWebAccess){								
								$daoWebChatMessageNotify->delByAccessId($dboWebAccess->getWebAccessId());
								$daoWebAccess->delByAccessId($dboWebAccess->getWebAccessId()); 
							}
						}
					}
					
				}	
			}
		}
	}
?>