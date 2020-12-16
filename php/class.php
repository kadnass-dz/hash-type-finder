<?php

class HashTaye {
private $CRC_16="/^[a-f0-9]{4}$/";

private $Adler_32="/^[a-f0-9]{8}$/";

private $CRC_24="/^[a-f0-9]{6}$/";

private $CRC_32="/^(\$crc32\$[a-f0-9]{8}.)?[a-f0-9]{8}$/";

private $Eggdrop_IRC_Bot="/^\+[a-z0-9\/.]{12}$/";

private $DES_Unix="/^[a-z0-9\/.]{13}$'/";

private $MySQL323="/^[a-f0-9]{16}$/";

private $Cisco_PIX_MD5="/^[a-z0-9\/.]{16}$/";

private $Lotus_Notes_Domino_6="/^\([a-z0-9\/+]{20}\)$/";

private $BSDi_Crypt="/^_[a-z0-9\/.]{19}$/";

private $CRC_96_ZIP="/^[a-f0-9]{24}$/";

private $Crypt16="/^[a-z0-9\/.]{24}$/"; 

private $MD2="/^(\$md2\$)?[a-f0-9]{32}$/";

private $MD5="/^[a-f0-9]{32}(:.+)?$/";

private $Snefru_128="/^(\$snefru\$)?[a-f0-9]{32}$/";

private $NTLM="/^(\$NT\$)?[a-f0-9]{32}$/";

private $Domain_Cached_Credentials='/^([^\\\/:*?"<>|]{1,20}:)?[a-f0-9]{32}(:[^\\\/:*?"<>|]{1,20})?$/';

private $Domain_Cached_Credentials_2='/^([^\\\/:*?"<>|]{1,20}:)?(\$DCC2\$10240#[^\\\/:*?"<>|]{1,20}#)?[a-f0-9]{32}$/';

private $SHA_1_Base64="/^{SHA}[a-z0-9\/+]{27}=$/";

private $MD5_Crypt="/^\$1\$[a-z0-9\/.]{0,8}\$[a-z0-9\/.]{22}(:.*)?$/";

private $Lineage_II_C4="/^0x[a-f0-9]{32}$/";

private $phpBB_v3_x="/^\$H\$[a-z0-9\/.]{31}$/";

private $Wordpress_v2_6_2="/^\$P\$[a-z0-9\/.]{31}$/";

private $osCommerce="/[a-f0-9]{32}:[a-z0-9]{2}$/";

private $MD5_APR="/^\$apr1\$[a-z0-9\/.]{0,8}\$[a-z0-9\/.]{22}$/";

private $AIX_smd5="/^{smd5}[a-z0-9$\/.]{31}$/";

private $WebEdition_CMS = "/^[a-f0-9]{32}:[a-f0-9]{32}$/";

private $IP_Board = "/^[a-f0-9]{32}:.{5}$/";

private $MyBB = "/^[a-f0-9]{32}:.{8}$/";

private $CryptoCurrency_Adress = "/^[a-z0-9]{34}$/";

private $SHA_1 = "/^[a-f0-9]{40}(:.+)?$/";

private $MySQL5_x = "/^\*[a-f0-9]{40}$/";

private $Cisco_IOS_SHA_256 = "/^[a-z0-9]{43}$/";

private $SSHA_1_Base64 = "/^{SSHA}[a-z0-9\/+]{38}==$/";

private $Fortigate_FortiOS = "/^[a-z0-9=]{47}$/";

private $Haval_192 = "/^[a-f0-9]{48}$/";

private $Palshop_CMS = "/^[a-f0-9]{51}$/";

private $CryptoCurrency_PrivateKey = "/^[a-z0-9]{51}$/";

private $AIX_ssha1 = "/^{ssha1}[0-9]{2}\$[a-z0-9$\/.]{44}$/";

private $MSSQL_2005 = "/^0x0100[a-f0-9]{48}$/";

private $Sun_MD5_Crypt = "/^(\$md5,rounds=[0-9]+\$|\$md5\$rounds=[0-9]+\$|\$md5\$)[a-z0-9\/.]{0,16}(\$|\$\$)[a-z0-9\/.]{22}$/";

private $SHA_224 = "/^[a-f0-9]{56}$/";

private $Blowfish_OpenBSD = "/^(\$2[axy]|\$2)\$[0-9]{2}\$[a-z0-9\/.]{53}$/";

private $Android_PIN = "/^[a-f0-9]{40}:[a-f0-9]{16}$/";

private $Oracle_11g_12c = "/^(S:)?[a-f0-9]{40}(:)?[a-f0-9]{20}$/";

private $bcrypt_SHA_256 = "/^\$bcrypt-sha256\$(2[axy]|2)\,[0-9]+\$[a-z0-9\/.]{22}\$[a-z0-9\/.]{31}$/";

private $vBulletin_v3_8_5 = "/^[a-f0-9]{32}:.{3}$/";

private $vBulletin_v3_8 = "/^[a-f0-9]{32}:.{30}$/";

private $Snefru_256 = "/\$snefru\$)?[a-f0-9]{64}$/";

private $SHA_256 = "/^[a-f0-9]{64}(:.+)?$/";

private $Joomla_v2_5_18 = "/^[a-f0-9]{32}:[a-z0-9]{32}$/";

private $SAM_LM_Hash_NT_Hash = "/^[a-f-0-9]{32}:[a-f-0-9]{32}$/";

private $MD5_Chap = "/^(\$chap\$0\*)?[a-f0-9]{32}[\*:][a-f0-9]{32}(:[0-9]{2})?$/";

private $EPiServer_6_x_v4 = "/^\$episerver\$\*0\*[a-z0-9\/=+]+\*[a-z0-9\/=+]{27,28}$/";

private $AIX_ssha256 ="/^{ssha256}[0-9]{2}\$[a-z0-9$\/.]{60}$/";

private $RIPEMD_320 ="/^[a-f0-9]{80}$/";

private $EPiServer_6_x_v ="/^\$episerver\$\*1\*[a-z0-9\/=+]+\*[a-z0-9\/=+]{42,43}$/";

private $MSSQL_2000 ="/'^0x0100[a-f0-9]{88}$/";

private $SHA_384 ="/^[a-f0-9]{96}$/";

private $SSHA_512_Base64 ="/^{SSHA512}[a-z0-9\/+]{96}$/";

private $AIX_ssha512 ="/^{ssha512}[0-9]{2}\$[a-z0-9\/.]{16,48}\$[a-z0-9\/.]{86}$/";

private $SHA_512 ="/^[a-f0-9]{128}(:.+)?$/";

private $OSX_v10_7 ="/^[a-f0-9]{136}$/";

private $MSSQL_2012 ="/^0x0200[a-f0-9]{136}$/";

private $OSX_v10_8 ="/^\$ml\$[0-9]+\$[a-f0-9]{64}\$[a-f0-9]{128}$/";

private $Skein_1024 ="/^[a-f0-9]{256}$/";

private $GRUB_2 ="/^grub\.pbkdf2\.sha512\.[0-9]+\.([a-f0-9]{128,2048}\.|[0-9]+\.)?[a-f0-9]{128}$/";

private $Django_SHA_1 ="/^sha1\$[a-z0-9]+\$[a-f0-9]{40}$/";

private $Citrix_Netscaler ="/^[a-f0-9]{49}$/";

private $Drupal_v7_x ="/^\$S\$[a-z0-9\/.]{52}$/";

private $SHA_256_Crypt ="/^\$5\$(rounds=[0-9]+\$)?[a-z0-9\/.]{0,16}\$[a-z0-9\/.]{43}$/";

private $Sybase_ASE ="/^0x[a-f0-9]{4}[a-f0-9]{16}[a-f0-9]{64}$/";

private $SHA_512_Crypt ="/^\$6\$(rounds=[0-9]+\$)?[a-z0-9\/.]{0,16}\$[a-z0-9\/.]{86}$/";
 
private $Minecraft_AuthMe_Reloaded = "/^\$sha\$[a-z0-9]{1,16}\$([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128}|[a-f0-9]{140})$/";

private $Django_SHA_256 ="/^sha256\$[a-z0-9]+\$[a-f0-9]{64}$/";

private $Django_SHA_384 ="/'^sha384\$[a-z0-9]+\$[a-f0-9]{96}$/";

private $Clavister_Secure_Gateway ="/^crypt1:[a-z0-9+=]{12}:[a-z0-9+=]{12}$/";

private $Cisco_VPN_Client_PCF_File ="/^[a-f0-9]{112}$/";

private $Microsoft_MSTSC_RDP_File = "/^[a-f0-9]{1329}$/";

private $NetNTLMv2 = '/^([^\\\/:*?"<>|]{1,20}\\)?[^\\\/:*?"<>|]{1,20}[:]{2,3}([^\\\/:*?"<>|]{1,20}:)?[^\\\/:*?"<>|]{1,20}:[a-f0-9]{32}:[a-f0-9]+$/';

private $Kerberos_5_AS_REQ_Pre_Auth = "/^\$(krb5pa|mskrb5)\$([0-9]{2})?\$.+\$[a-f0-9]{1,}$/";

private $SCRAM_Hash = "/^\$scram\$[0-9]+\$[a-z0-9\/.]{16}\$sha-1=[a-z0-9\/.]{27},sha-256=[a-z0-9\/.]{43},sha-512=[a-z0-9\/.]{86}$/";

private $Redmine_Project_Management_Web_App = "/^[a-f0-9]{40}:[a-f0-9]{0,32}$/";

private $SAP_CODVN_B_BCODE = "/^(.+)?\$[a-f0-9]{16}$/";

private $SAP_CODVN_F_G = "/^(.+)?\$[a-f0-9]{40}$/";

private $Juniper_Netscreen_SSG_ScreenOS = "/^(.+\$)?[a-z0-9\/.+]{30}(:.+)?$/";

private $EPi = "/^0x[a-f0-9]{60}\s0x[a-f0-9]{40}$/";

private $SMF_v1_1 = "/^[a-f0-9]{40}:[^*]{1,25}$/";

private $Woltlab_Burning_Board_3_x = "/^(\$wbb3\$\*1\*)?[a-f0-9]{40}[:*][a-f0-9]{40}$/";

private $IPMI2_RAKP_HMAC_SHA1 = "/^[a-f0-9]{130}(:[a-f0-9]{40})?$/";

private $Lastpass = "/^[a-f0-9]{32}:[0-9]+:[a-z0-9_.+-]+@[a-z0-9-]+\.[a-z0-9-.]+$/";

private $Cisco_ASA_MD5 = "/^[a-z0-9\/.]{16}([:$].{1,})?$/";

private $VNC = "/^\$vnc\$\*[a-f0-9]{32}\*[a-f0-9]{32}$/";

private $DNSSEC = "/^[a-z0-9]{32}(:([a-z0-9-]+\.)?[a-z0-9-.]+\.[a-z]{2,7}:.+:[0-9]+)?$/";

private $RACF = "/^(user-.+:)?\$racf\$\*.+\*[a-f0-9]{16}$/";

private $NTHash_FreeBSD_Variant = "/^\$3\$\$[a-f0-9]{32}$/";

private $SHA_1_Crypt = "/^\$sha1\$[0-9]+\$[a-z0-9\/.]{0,64}\$[a-z0-9\/.]{28}$/";

private $hMailServer = "/^[a-f0-9]{70}$/";

private $MediaWiki = "/^[:\$][AB][:\$]([a-f0-9]{1,8}[:\$])?[a-f0-9]{32}$/";

private $Minecraft_xAuth = "/^[a-f0-9]{140}$/";

private $PBKDF2_SHA1_Generic = "/^\$pbkdf2(-sha1)?\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{27}$/";

private $PBKDF2_SHA256_Generic = "/^\$pbkdf2-sha256\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{43}$/";

private $PBKDF2_SHA512_Generic = "/^\$pbkdf2-sha512\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{86}$/";

private $PBKDF2_Cryptacular = "/^\$p5k2\$[0-9]+\$[a-z0-9\/+=-]+\$[a-z0-9\/+-]{27}=$/";

private $PBKDF2_Dwayne_Litzenberger = "/^\$p5k2\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{32}$/";

private $Fairly_Secure_Hashed_Password = "/^{FSHP[0123]\|[0-9]+\|[0-9]+}[a-z0-9\/+=]+$/";

private $PHPS = "/^\$PHPS\$.+\$[a-f0-9]{32}$/";

private $Password_Agile_Keychain = "/^[0-9]{4}:[a-f0-9]{16}:[a-f0-9]{2080}$/";

private $Password_Cloud_Keychain = "/^[a-f0-9]{64}:[a-f0-9]{32}:[0-9]{5}:[a-f0-9]{608}$/";

private $IKE_PSK_MD5 = "/^[a-f0-9]{256}:[a-f0-9]{256}:[a-f0-9]{16}:[a-f0-9]{16}:[a-f0-9]{320}:[a-f0-9]{16}:[a-f0-9]{40}:[a-f0-9]{40}:[a-f0-9]{32}$/";

private $IKE_PSK_SHA1 = "/^[a-f0-9]{256}:[a-f0-9]{256}:[a-f0-9]{16}:[a-f0-9]{16}:[a-f0-9]{320}:[a-f0-9]{16}:[a-f0-9]{40}:[a-f0-9]{40}:[a-f0-9]{40}$/";

private $PeopleSoft = "/^[a-z0-9\/+]{27}=$/";

private $Django_DES_Crypt_Wrapper = "/^crypt\$[a-f0-9]{5}\$[a-z0-9\/.]{13}$/";

private $Django_PBKDF2_HMAC_SHA256 = "/^(\$django\$\*1\*)?pbkdf2_sha256\$[0-9]+\$[a-z0-9]+\$[a-z0-9\/+=]{44}$/";

private $Django_PBKDF2_HMAC_SHA1 = "/^pbkdf2_sha1\$[0-9]+\$[a-z0-9]+\$[a-z0-9\/+=]{28}$/";

private $Django_bcrypt = "/^bcrypt(\$2[axy]|\$2)\$[0-9]{2}\$[a-z0-9\/.]{53}$/";

private $Django_MD5 = "/^md5\$[a-f0-9]+\$[a-f0-9]{32}$/";

private $PBKDF2_Atlassian = "/^\{PKCS5S2\}[a-z0-9\/+]{64}$/";

private $PostgreSQL_MD5 = "/^md5[a-f0-9]{32}$/";

private $Lotus_Notes_Domino_8 = "/^\([a-z0-9\/+]{49}\)$/";

private $scrypt = "/^SCRYPT:[0-9]{1,}:[0-9]{1}:[0-9]{1}:[a-z0-9:\/+=]{1,}$/";

private $Cisco_Type_8 = "/^\$8\$[a-z0-9\/.]{14}\$[a-z0-9\/.]{43}$/";

private $Cisco_Type_9 = "/^\$9\$[a-z0-9\/.]{14}\$[a-z0-9\/.]{43}$/";

private $Microsoft_Office_2007 = "/^\$office\$\*2007\*[0-9]{2}\*[0-9]{3}\*[0-9]{2}\*[a-z0-9]{32}\*[a-z0-9]{32}\*[a-z0-9]{40}$/";

private $Microsoft_Office_2010 = "/^\$office\$\*2010\*[0-9]{6}\*[0-9]{3}\*[0-9]{2}\*[a-z0-9]{32}\*[a-z0-9]{32}\*[a-z0-9]{64}$/";

private $Microsoft_Office_2013 = "/^\$office\$\*2013\*[0-9]{6}\*[0-9]{3}\*[0-9]{2}\*[a-z0-9]{32}\*[a-z0-9]{32}\*[a-z0-9]{64}$/";

private $Android_FDE_4_3 = "/^\$fde\$[0-9]{2}\$[a-f0-9]{32}\$[0-9]{2}\$[a-f0-9]{32}\$[a-f0-9]{3072}$/";

private $Microsoft_Office_2003_MD5_RC4 = "/^\$oldoffice\$[01]\*[a-f0-9]{32}\*[a-f0-9]{32}\*[a-f0-9]{32}$/";

private $Microsoft_Office_2003_SHA1_RC4 = "/^\$oldoffice\$[34]\*[a-f0-9]{32}\*[a-f0-9]{32}\*[a-f0-9]{40}$/";

private $RAdmin_v2_x = "/^(\$radmin2\$)?[a-f0-9]{32}$/";

private $SAP_CODVN_H = "/^{x-issha,\s[0-9]{4}}[a-z0-9\/+=]+$/";

private $CRAM_MD5 = "/^\$cram_md5\$[a-z0-9\/+=-]+\$[a-z0-9\/+=-]{52}$/";

private $SipHash = "/^[a-f0-9]{16}:2:4:[a-f0-9]{32}$/";

private $Cisco_Type_7 = "/^[a-f0-9]{4,}$/";

private $Cisco_Type_4 = "/^(\$cisco4\$)?[a-z0-9\/.]{43}$/";

private $Django_bcrypt_SHA256 = "/^bcrypt_sha256\$\$(2[axy]|2)\$[0-9]+\$[a-z0-9\/.]{53}$/";

private $PostgreSQL_Challenge_Response_Authentication_MD5 = "/^\$postgres\$.[^\*]+[*:][a-f0-9]{1,32}[*:][a-f0-9]{32}$/";

private $Siemens_S7 = "/^\$siemens-s7\$[0-9]{1}\$[a-f0-9]{40}\$[a-f0-9]{40}$/";

private $Microsoft_Outlook_PST = "/^(\$pst\$)?[a-f0-9]{8}$/";

private $PBKDF2_HMAC_SHA256_PHP = "/^sha256[:$][0-9]+[:$][a-z0-9\/+]+[:$][a-z0-9\/+]{32,128}$/";

private $Dahua = "/^(\$dahua\$)?[a-z0-9]{8}$/";

private $MySQL_Challenge_Response_Authentication_sha1 = "/^\$mysqlna\$[a-f0-9]{40}[:*][a-f0-9]{40}$/";

private $PDF_1_4_1_6 = "/^\$pdf\$[24]\*[34]\*128\*[0-9-]{1,5}\*1\*(16|32)\*[a-f0-9]{32,64}\*32\*[a-f0-9]{64}\*(8|16|32)\*[a-f0-9]{16,64}$/";

/* ------------------ */
public function identify($ha)
{
			if (preg_match($this->CRC_16, $ha)){
			$data .= "CRC_16\r\n
			CRC-16-CCITT\r\n
			FCS-16";
			}

			if (preg_match($this->Adler_32, $ha)){
			$data .= "Adler-32\r\n
			CRC-32B\r\n
			FCS-32\r\n
			GHash-32-3\r\n
			GHash-32-5\r\n
			FNV-132\r\n
			Fletcher-32\r\n
			Joaat\r\n
			ELF-32\r\n
			XOR-32";
			}

			if (preg_match($this->CRC_24, $ha)){
			$data .= "CRC-24\r\n";
			}

			if (preg_match($this->CRC_32, $ha)){
			$data .= "CRC-32\r\n";
			}

			if (preg_match($this->Eggdrop_IRC_Bot, $ha)){
			$data .= "Eggdrop IRC Bot";
			}

			if (preg_match($this->DES_Unix, $ha)){
			$data .= "DES(Unix)\r\n
			Traditional DES\r\n
			DEScrypt";
			}

			if (preg_match($this->MySQL323, $ha)){
			$data .= "MySQL323\r\n
			DES(Oracle)\r\n
			Half MD5\r\n
			Oracle 7-10g\r\n
			FNV-164\r\n
			CRC-64\r\n";
			}

			if (preg_match($this->Cisco_PIX_MD5, $ha)){
			$data .= "Cisco-PIX(MD5)\r\n";
			}

			if (preg_match($this->Lotus_Notes_Domino_6, $ha)){
			$data .= "Lotus Notes/Domino 6\r\n";
			}

			if (preg_match($this->BSDi_Crypt, $ha)){
			$data .= "BSDi Crypt\r\n";
			}

			if (preg_match($this->CRC_96_ZIP, $ha)){
			$data .= "CRC-96(ZIP)\r\n";
			}

			if (preg_match($this->Crypt16, $ha)){
			$data .= "Crypt16\r\n";

			}

			if (preg_match($this->MD2, $ha)){
			$data .= "MD2\r\n";
			}

			if (preg_match($this->MD5, $ha)){
			$data .= 'MD5
			MD4
			Double MD5
						LM
						RIPEMD-128
						Haval-128
						Tiger-128
						Skein-256(128)
						Skein-512(128)
						Lotus Notes/Domino 5
						Skype
						ZipMonster
						PrestaShop
						md5(md5(md5($pass)))
						md5(strtoupper(md5($pass)))
						md5(sha1($pass))
						md5($pass.$salt)
						md5($salt.$pass)
						md5(unicode($pass).$salt)
						md5($salt.unicode($pass))
						HMAC-MD5 (key = $pass)
						HMAC-MD5 (key = $salt)
						md5(md5($salt).$pass)
						md5($salt.md5($pass))
						md5($pass.md5($salt))
						md5($salt.$pass.$salt)
						md5(md5($pass).md5($salt))
						md5($salt.md5($salt.$pass))
						md5($salt.md5($pass.$salt))
						md5($username.0.$pass)\r\n';
			}

			if (preg_match($this->Snefru_128, $ha)){
			$data .= "\r\nSnefru-128\r\n";
			}

			if (preg_match($this->NTLM, $ha)){
			$data .= "NTLM\r\n";
			}

			if (preg_match($this->Domain_Cached_Credentials, $ha)){
			$data .= "Domain Cached Credentials\r\n";
			}

			if (preg_match($this->Domain_Cached_Credentials_2, $ha)){
			$data .= "Domain Cached Credentials 2\r\n";
			}

			if (preg_match($this->SHA_1_Base64, $ha)){
			$data .= "SHA-1(Base64)\r\n
			Netscape LDAP SHA\r\n";
			}

			if (preg_match($this->MD5_Crypt, $ha)){
			$data .= "MD5 Crypt\r\n
			Cisco-IOS(MD5)\r\n
			FreeBSD MD5\r\n";
			}

			if (preg_match($this->Lineage_II_C4, $ha)){
			$data .= "Lineage II C4\r\n";
			}

			if (preg_match($this->phpBB_v3_x, $ha)){
			$data .= "phpBB v3.x\r\n
			Wordpress v2.6.0/2.6.1\r\n
			PHPass' Portable Hash\r\n";
			}

			if (preg_match($this->Wordpress_v2_6_2, $ha)){
			$data .= "Wordpress ≥ v2.6.2\r\n
			Joomla ≥ v2.5.18\r\n
			PHPass' Portable Hash\r\n";
			}

			if (preg_match($this->osCommerce, $ha)){
			$data .= "osCommerce\r\n
			xt:Commerce\r\n";
			}

			if (preg_match($this->MD5_APR, $ha)){
			$data .= "MD5(APR)
					  Apache MD5
					  md5apr\r\n";
			}

			if (preg_match($this->AIX_smd5, $ha)){
			$data .= "AIX(smd5)\r\n";
			}		

			if (preg_match($this->WebEdition_CMS, $ha)){
			$data .= "WebEdition CMS\r\n";
			}		

			if (preg_match($this->IP_Board, $ha)){
			$data .= "IP.Board ≥ v2+\r\n";
			}		

			if (preg_match($this->MyBB, $ha)){
			$data .= "MyBB ≥ v1.2+\r\n";
			}		

			if (preg_match($this->CryptoCurrency_Adress, $ha)){
			$data .= "CryptoCurrency(Adress)\r\n";
			}		

			if (preg_match($this->SHA_1, $ha)){
			$data .= "
					SHA-1
					Double SHA-1
					RIPEMD-160
					Haval-160
					Tiger-160
					HAS-160
					LinkedIn
					Skein-256(160)
					Skein-512(160)
					MangosWeb Enhanced CMS
					sha1(sha1(sha1($pass)))
					sha1(md5($pass))
					sha1($pass.$salt)
					sha1($salt.$pass)
					sha1(unicode($pass).$salt)
					sha1($salt.unicode($pass))
					HMAC-SHA1 (key = $pass)
					HMAC-SHA1 (key = $salt)
					sha1($salt.$pass.$salt)\r\n";
			}		

			if (preg_match($this->MySQL5_x, $ha)){
			$data .= "MySQL5.x'
					  MySQL4.1\r\n";
			}		

			if (preg_match($this->Cisco_IOS_SHA_256 , $ha)){
			$data .= "Cisco-IOS(SHA-256)\r\n";
			}		

			if (preg_match($this->SSHA_1_Base64, $ha)){
			$data .= "SSHA-1(Base64)
					  Netscape LDAP SSHA
                      nsldaps\r\n";
			}		

			if (preg_match($this->Fortigate_FortiOS, $ha)){
			$data .= "Fortigate(FortiOS)\r\n";
			}		

			if (preg_match($this->Haval_192, $ha)){
			$data .= "	Haval-192
						Tiger-192
						SHA-1(Oracle)
						OSX v10.4
						OSX v10.5
						OSX v10.6\r\n";
			}		

			if (preg_match($this->Palshop_CMS, $ha)){
			$data .= "Palshop CMS\r\n";
			}		

			if (preg_match($this->CryptoCurrency_PrivateKey, $ha)){
			$data .= "CryptoCurrency(PrivateKey)\r\n";
			}		

			if (preg_match($this->AIX_ssha1, $ha)){
			$data .= "AIX(ssha1)\r\n";
			}		

			if (preg_match($this->MSSQL_2005, $ha)){
			$data .= "MSSQL(2005)
					  MSSQL(2008)\r\n";
			}		

			if (preg_match($this->Sun_MD5_Crypt, $ha)){
			$data .= "Sun MD5 Crypt\r\n";
			}		

			if (preg_match($this->SHA_224, $ha)){
			$data .= "SHA-224
					  Haval-224
					  SHA3-224
					  Skein-256(224)
					  Skein-512(224)\r\n";
			}		

			if (preg_match($this->Blowfish_OpenBSD, $ha)){
			$data .= "Blowfish(OpenBSD)
					  Woltlab Burning Board 4.x
					  bcrypt\r\n";
			}		

			if (preg_match($this->Android_PIN, $ha)){
			$data .= "Android PIN\r\n";
			}		

			if (preg_match($this->Oracle_11g_12c, $ha)){
			$data .= "Oracle 11g/12c\r\n";
			}		

			if (preg_match($this->bcrypt_SHA_256, $ha)){
			$data .= "bcrypt(SHA-256)\r\n";
			}		

			if (preg_match($this->vBulletin_v3_8_5, $ha)){
			$data .= "vBulletin < v3.8.5\r\n";
			}

			if (preg_match($this->vBulletin_v3_8, $ha)){
			$data .= "vBulletin ≥ v3.8.5\r\n";
			}

			if (preg_match($this->Snefru_256, $ha)){
			$data .= "Snefru-256\r\n\r\n";
			}

			if (preg_match($this->SHA_256, $ha)){
			$data .= '
				SHA-256
				RIPEMD-256
				Haval-256
				GOST R 34.11-94
				GOST CryptoPro S-Box
				SHA3-256
				Skein-256
				Skein-512(256)
				Ventrilo
				sha256($pass.$salt)
				sha256($salt.$pass)
				sha256(unicode($pass).$salt)
				ha256($salt.unicode($pass))
				HMAC-SHA256 (key = $pass)
				HMAC-SHA256 (key = $salt)
									\r\n';
			}

			if (preg_match($this->Joomla_v2_5_18, $ha)){
			$data .= "Joomla < v2.5.18\r\n";
			}

			if (preg_match($this->SAM_LM_Hash_NT_Hash, $ha)){
			$data .= "SAM(LM_Hash:NT_Hash)\r\n";
			}

			if (preg_match($this->MD5_Chap, $ha)){
			$data .= "MD5(Chap)
					  iSCSI CHAP Authentication\r\n";
			}
			
			if (preg_match($this->EPiServer_6_x_v4, $ha)){
			$data .= "EPiServer 6.x < v4\r\n";
			}
			
			if (preg_match($this->AIX_ssha256, $ha)){
			$data .= "AIX(ssha256)\r\n";
			}
			
			if (preg_match($this->RIPEMD_320, $ha)){
			$data .= "RIPEMD-320\r\n";
			}
			
			if (preg_match($this->EPiServer_6_x_v, $ha)){
			$data .= "EPiServer 6.x ≥ v4\r\n";
			}
			
			if (preg_match($this->MSSQL_2000, $ha)){
			$data .= "MSSQL(2000)\r\n";
			}
			
			if (preg_match($this->SHA_384, $ha)){
			$data .= "SHA-384
						SHA3-384
						Skein-512(384)
						Skein-1024(384)\r\n";
			}
			
			if (preg_match($this->SSHA_512_Base64, $ha)){
			$data .= "SSHA-512(Base64)
					 LDAP(SSHA-512)\r\n";
			}
			
			if (preg_match($this->AIX_ssha512, $ha)){
			$data .= "AIX(ssha512)\r\n";
			}
			
			if (preg_match($this->SHA_512, $ha)){
			$data .= '
					SHA-512
					Whirlpool
					Salsa10
					Salsa20
					SHA3-512
					Skein-512
					Skein-1024(512)
					sha512($pass.$salt)
					sha512($salt.$pass)
					sha512(unicode($pass).$salt)
					sha512($salt.unicode($pass))
					HMAC-SHA512 (key = $pass)
					HMAC-SHA512 (key = $salt)\r\n';
			}
			
			if (preg_match($this->OSX_v10_7, $ha)){
			$data .= "OSX v10.7\r\n";
			}
			
			if (preg_match($this->MSSQL_2012, $ha)){
			$data .= "MSSQL(2012)
						MSSQL(2014)\r\n";
			}
			
			if (preg_match($this->OSX_v10_8, $ha)){
			$data .= "OSX v10.8
						OSX v10.9\r\n";
			}
			
			if (preg_match($this->Skein_1024, $ha)){
			$data .= "Skein-1024\r\n";
			}
			
			if (preg_match($this->GRUB_2, $ha)){
			$data .= "GRUB 2\r\n";
			}
			
			if (preg_match($this->Django_SHA_1, $ha)){
			$data .= "Django(SHA-1)\r\n";
			}
			
			if (preg_match($this->Citrix_Netscaler, $ha)){
			$data .= "Citrix Netscaler\r\n";
			}
			
			if (preg_match($this->Drupal_v7_x, $ha)){
			$data .= "Drupal > v7.x\r\n";
			}
			
			if (preg_match($this->SHA_256_Crypt, $ha)){
			$data .= "SHA-256 Crypt\r\n";
			}
			
			if (preg_match($this->Sybase_ASE, $ha)){
			$data .= "Sybase ASE\r\n";
			}
			
			if (preg_match($this->SHA_512_Crypt, $ha)){
			$data .= "SHA-512 Crypt\r\n";
			}
			
			if (preg_match($this->Minecraft_AuthMe_Reloaded, $ha)){
			$data .= "Minecraft(AuthMe Reloaded)\r\n";
			}
			
			if (preg_match($this->Django_SHA_256, $ha)){
			$data .= "Django(SHA-256)\r\n";
			}
			
			if (preg_match($this->Django_SHA_384, $ha)){
			$data .= "Django(SHA-384)\r\n";
			}
			
			if (preg_match($this->Clavister_Secure_Gateway, $ha)){
			$data .= "Clavister Secure Gateway\r\n";
			}
			
			if (preg_match($this->Cisco_VPN_Client_PCF_File, $ha)){
			$data .= "Cisco VPN Client(PCF-File)\r\n";
			}
			
			if (preg_match($this->Microsoft_MSTSC_RDP_File, $ha)){
			$data .= "Microsoft MSTSC(RDP-File)\r\n";
			}
			
			if (preg_match($this->NetNTLMv2, $ha)){
			$data .= "NetNTLMv2\r\n";
			}
			
			if (preg_match($this->Kerberos_5_AS_REQ_Pre_Auth, $ha)){
			$data .= "Kerberos 5 AS-REQ Pre-Auth\r\n";
			}
			
			if (preg_match($this->SCRAM_Hash, $ha)){
			$data .= "SCRAM Hash\r\n";
			}
			
			if (preg_match($this->Snefru_256, $ha)){
			$data .= "Snefru-256\r\n";
			}			
			if (preg_match($this->Snefru_256, $ha)){
			$data .= "Snefru-256\r\n";
			}
			
			if (preg_match($this->Snefru_256, $ha)){
			$data .= "Snefru-256\r\n";
			}
			
			if (preg_match($this->Redmine_Project_Management_Web_App, $ha)){
			$data .= "Redmine Project Management Web App\r\n";
			}
			
			if (preg_match($this->SAP_CODVN_B_BCODE, $ha)){
			$data .= "SAP CODVN B (BCODE)\r\n";
			}
			
			if (preg_match($this->SAP_CODVN_F_G, $ha)){
			$data .= "SAP CODVN F/G (PASSCODE)\r\n";
			}

			if (preg_match($this->Juniper_Netscreen_SSG_ScreenOS, $ha)){
			$data .= "Juniper Netscreen/SSG(ScreenOS)\r\n";
			}
			
			if (preg_match($this->EPi, $ha)){
			$data .= "EPi\r\n";
			}

			if (preg_match($this->SMF_v1_1, $ha)){
			$data .= "SMF ≥ v1.1\r\n";
			}
			
			if (preg_match($this->Woltlab_Burning_Board_3_x, $ha)){
			$data .= "Woltlab Burning Board 3.x\r\n";
			}

			if (preg_match($this->IPMI2_RAKP_HMAC_SHA1, $ha)){
			$data .= "IPMI2 RAKP HMAC-SHA1\r\n";
			}
			
			if (preg_match($this->Lastpass, $ha)){
			$data .= "Lastpass\r\n";
			}

			if (preg_match($this->Cisco_ASA_MD5, $ha)){
			$data .= "Cisco-ASA(MD5)\r\n";
			}
			
			if (preg_match($this->VNC, $ha)){
			$data .= "VNC\r\n";
			}

			if (preg_match($this->DNSSEC, $ha)){
			$data .= "DNSSEC(NSEC3)\r\n";
			}
			
			if (preg_match($this->RACF, $ha)){
			$data .= "RACF\r\n";
			}

			if (preg_match($this->NTHash_FreeBSD_Variant, $ha)){
			$data .= "NTHash(FreeBSD Variant)\r\n";
			}
			
			if (preg_match($this->SHA_1_Crypt, $ha)){
			$data .= "SHA-1 Crypt\r\n";
			}

			if (preg_match($this->hMailServer, $ha)){
			$data .= "hMailServer\r\n";
			}
			
			if (preg_match($this->MediaWiki, $ha)){
			$data .= "MediaWiki\r\n";
			}

			if (preg_match($this->Minecraft_xAuth, $ha)){
			$data .= "Minecraft(xAuth)\r\n";
			}
			
			if (preg_match($this->PBKDF2_SHA1_Generic, $ha)){
			$data .= "PBKDF2-SHA1(Generic)\r\n";
			}

			if (preg_match($this->PBKDF2_SHA256_Generic, $ha)){
			$data .= "PBKDF2-SHA256(Generic)\r\n";
			}
			
			if (preg_match($this->PBKDF2_SHA512_Generic , $ha)){
			$data .= "PBKDF2-SHA512(Generic)\r\n";
			}

			if (preg_match($this->PBKDF2_Cryptacular, $ha)){
			$data .= "PBKDF2(Cryptacular)\r\n";
			}
			
			if (preg_match($this->PBKDF2_Dwayne_Litzenberger, $ha)){
			$data .= "PBKDF2(Dwayne Litzenberger)\r\n";
			}

			if (preg_match($this->Fairly_Secure_Hashed_Password, $ha)){
			$data .= "Fairly Secure Hashed Password\r\n";
			}
			
			if (preg_match($this->PHPS, $ha)){
			$data .= "PHPS\r\n";
			}

			if (preg_match($this->Password_Agile_Keychain, $ha)){
			$data .= "1Password(Agile Keychain)\r\n";
			}
			
			if (preg_match($this->Password_Cloud_Keychain, $ha)){
			$data .= "1Password(Cloud Keychain)\r\n";
			}

			if (preg_match($this->IKE_PSK_MD5, $ha)){
			$data .= "IKE-PSK MD5\r\n";
			}
			
			if (preg_match($this->IKE_PSK_SHA1, $ha)){
			$data .= "IKE-PSK SHA1\r\n";
			}

			if (preg_match($this->PeopleSoft, $ha)){
			$data .= "PeopleSoft\r\n";
			}
			
			if (preg_match($this->Django_DES_Crypt_Wrapper, $ha)){
			$data .= "Django(DES Crypt Wrapper)\r\n";
			}

			if (preg_match($this->Django_PBKDF2_HMAC_SHA256, $ha)){
			$data .= "Django(PBKDF2-HMAC-SHA256)\r\n";
			}

			if (preg_match($this->Django_PBKDF2_HMAC_SHA1, $ha)){
			$data .= "Django(PBKDF2-HMAC-SHA1)\r\n";
			}
			
			if (preg_match($this->Django_bcrypt, $ha)){
			$data .= "Django(bcrypt)\r\n";
			}			
			if (preg_match($this->Django_MD5, $ha)){
			$data .= "Django (MD5)\r\n";
			}

			if (preg_match($this->PBKDF2_Atlassian, $ha)){
			$data .= "PBKDF2(Atlassian)\r\n";
			}
			
			if (preg_match($this->PostgreSQL_MD5, $ha)){
			$data .= "PostgreSQL MD5\r\n";
			}			
			if (preg_match($this->Lotus_Notes_Domino_8, $ha)){
			$data .= "Lotus Notes/Domino 8\r\n";
			}

			if (preg_match($this->scrypt, $ha)){
			$data .= "scrypt\r\n";
			}
			
			if (preg_match($this->Cisco_Type_8, $ha)){
			$data .= "Cisco Type 8\r\n";
			}			
			if (preg_match($this->Cisco_Type_9, $ha)){
			$data .= "Cisco Type 9\r\n";
			}

			if (preg_match($this->Microsoft_Office_2007, $ha)){
			$data .= "Microsoft Office 2007\r\n";
			}
			
			if (preg_match($this->Microsoft_Office_2010, $ha)){
			$data .= "Microsoft Office 2010\r\n";
			}			
			if (preg_match($this->Microsoft_Office_2013, $ha)){
			$data .= "Microsoft Office 2013\r\n";
			}

			if (preg_match($this->Android_FDE_4_3, $ha)){
			$data .= "Android FDE ≤ 4.3\r\n";
			}
			
			if (preg_match($this->Microsoft_Office_2003_MD5_RC4, $ha)){
			$data .= "Microsoft Office ≤ 2003 (MD5+RC4)
						Microsoft Office ≤ 2003 (MD5+RC4) collider-mode #1
						Microsoft Office ≤ 2003 (MD5+RC4) collider-mode #2\r\n";
			}			
			if (preg_match($this->Microsoft_Office_2003_SHA1_RC4, $ha)){
			$data .= "Microsoft Office ≤ 2003 (SHA1+RC4)
						Microsoft Office ≤ 2003 (SHA1+RC4) collider-mode #1
						Microsoft Office ≤ 2003 (SHA1+RC4) collider-mode #2\r\n";
			}

			if (preg_match($this->RAdmin_v2_x, $ha)){
			$data .= "RAdmin v2.x\r\n";
			}
			
			if (preg_match($this->SAP_CODVN_H, $ha)){
			$data .= "SAP CODVN H (PWDSALTEDHASH) iSSHA-1\r\n";
			}			
			if (preg_match($this->CRAM_MD5, $ha)){
			$data .= "CRAM-MD5\r\n";
			}

			if (preg_match($this->SipHash, $ha)){
			$data .= "SipHash\r\n";
			}
			
			if (preg_match($this->Cisco_Type_7, $ha)){
			$data .= "Cisco Type 7\r\n";
			}			
			if (preg_match($this->Cisco_Type_4, $ha)){
			$data .= "Cisco Type 4\r\n";
			}

			if (preg_match($this->Django_bcrypt_SHA256, $ha)){
			$data .= "Django(bcrypt-SHA256)\r\n";
			}
			
			if (preg_match($this->PostgreSQL_Challenge_Response_Authentication_MD5, $ha)){
			$data .= "PostgreSQL Challenge-Response Authentication (MD5)\r\n";
			}			
			if (preg_match($this->Siemens_S7, $ha)){
			$data .= "Siemens S7\r\n";
			}

			if (preg_match($this->Microsoft_Outlook_PST, $ha)){
			$data .= "Microsoft Outlook PST\r\n";
			}
			
			if (preg_match($this->PBKDF2_HMAC_SHA256_PHP, $ha)){
			$data .= "PBKDF2-HMAC-SHA256(PHP)\r\n";
			}			
			if (preg_match($this->Dahua, $ha)){
			$data .= "Dahua\r\n";
			}

			if (preg_match($this->MySQL_Challenge_Response_Authentication_sha1, $ha)){
			$data .= "MySQL Challenge-Response Authentication (SHA1)\r\n";
			}
			
			if (preg_match($this->PDF_1_4_1_6, $ha)){
			$data .= "PDF 1.4 - 1.6 (Acrobat 5 - 8)\r\n";
			}

			return !empty($data) ? "# Your hash may be one of the following:</br>" .$data : 'Not Found ! Sorry This Hash Type Unknown :/' ;
			
	}

}
//phinshid 

if (isset($_POST['hash'])) {
sleep(1);
$h = $_POST['hash'];
$chek= new HashTaye();
$result=nl2br($chek->identify($h));
echo "<div class='res'>".$result." <br> ../ Done </div>";

}
