package service

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"strconv"
	"strings"
	"time"

	"github.com/Jeffail/gabs/v2"
	"github.com/sipcapture/homer-app/config"
	"github.com/sipcapture/homer-app/utils/heputils"
	"github.com/sipcapture/homer-app/utils/httpauth"
	"github.com/sipcapture/homer-app/utils/logger"

	"github.com/sipcapture/homer-app/auth"
	"github.com/sipcapture/homer-app/model"
	"github.com/sipcapture/homer-app/utils/ldap"
	"golang.org/x/crypto/bcrypt"
)

type UserService struct {
	ServiceConfig
	LdapClient *ldap.LDAPClient
	HttpAuth   *httpauth.Client
}

// this method gets all users from database
func (us *UserService) GetUser(UserName string, isAdmin bool) ([]*model.TableUser, int, error) {

	var user []*model.TableUser
	var sqlWhere = make(map[string]interface{})

	if !isAdmin {
		sqlWhere = map[string]interface{}{"username": UserName}
	}

	if err := us.Session.Debug().Table("users").Where(sqlWhere).Find(&user).Error; err != nil {
		return user, 0, err
	}

	return user, len(user), nil
}

// this method checks if a user is admin using the email address
func (us *UserService) IsAdmin(email string) (bool, error) {

	var user []*model.TableUser
	var sqlWhere = make(map[string]interface{})

	sqlWhere = map[string]interface{}{"email": email}

	if err := us.Session.Debug().Table("users").Where(sqlWhere).Find(&user).Error; err != nil {
		return false, err
	}

	if len(user) != 1 {
		return false, nil
	}

	return user[0].UserGroup != "" && strings.Contains(strings.ToLower(user[0].UserGroup), "admin"), nil
}

// this method gets all users from database
func (us *UserService) GetUserByUUID(GUID, UserName string) ([]*model.TableUser, int, error) {

	var user []*model.TableUser

	if err := us.Session.Debug().Table("users").Where("username = ? AND guid = ?", UserName, GUID).Find(&user).Error; err != nil {
		return user, 0, err
	}

	return user, len(user), nil
}

/* get all */
func (us *UserService) GetGroups() (string, error) {

	count := len(config.Setting.MAIN_SETTINGS.UserGroups)
	reply := gabs.New()
	reply.Set(count, "count")
	reply.Set(config.Setting.MAIN_SETTINGS.UserGroups, "data")
	return reply.String(), nil
}

// this method create new user in the database
// it doesn't check internally whether all the validation are applied or not
func (us *UserService) CreateNewUser(user *model.TableUser) error {

	user.CreatedAt = time.Now()

	if user.Password == "" {
		return errors.New("empty password")
	}

	if !heputils.ElementRealExists(config.Setting.MAIN_SETTINGS.UserGroups, user.UserGroup) {
		logger.Error("create user with group that doesn't exist: ", user.UserGroup)
		return fmt.Errorf("the user group '%s' doesn't exist", user.UserGroup)
	}

	// lets generate hash from password
	password := []byte(user.Password)

	// Hashing the password with the default cost of 10
	hashedPassword, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	user.Hash = string(hashedPassword)

	err = us.Session.Debug().Table("users").Create(&user).Error
	if err != nil {
		return err
	}
	return nil
}

// this method update user info in the database
// it doesn't check internally whether all the validation are applied or not
func (us *UserService) UpdateUser(user *model.TableUser, UserName string, isAdmin bool) error {

	// get new instance of user data source
	user.CreatedAt = time.Now()
	oldRecord := model.TableUser{}

	var sqlWhere = make(map[string]interface{})

	if !isAdmin {
		sqlWhere = map[string]interface{}{"guid": user.GUID, "username": UserName}
	} else {
		sqlWhere = map[string]interface{}{"guid": user.GUID}
	}

	if us.Session.Where(sqlWhere).Find(&oldRecord).RecordNotFound() {
		return fmt.Errorf("the user with id '%s' was not found", user.GUID)
	}

	if !heputils.ElementRealExists(config.Setting.MAIN_SETTINGS.UserGroups, user.UserGroup) {
		logger.Error("create user with group that doesn't exist: ", user.UserGroup)
		return fmt.Errorf("the user group '%s' doesn't exist", user.UserGroup)
	}

	if user.Password != "" {
		password := []byte(user.Password)
		// Hashing the password with the default cost of 10
		hashedPassword, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		user.Hash = string(hashedPassword)
	} else {
		user.Hash = oldRecord.Hash
	}
	if !isAdmin {
		err := us.Session.Debug().Table("users").Model(&model.TableUser{}).Where(sqlWhere).Update(model.TableUser{Email: user.Email, FirstName: user.FirstName,
			LastName: user.LastName, Department: user.Department, Hash: user.Hash, CreatedAt: user.CreatedAt, Enabled: user.Enabled}).Error
		if err != nil {
			return err
		}
	} else {
		err := us.Session.Debug().Table("users").Model(&model.TableUser{}).Where(sqlWhere).Update(model.TableUser{UserName: user.UserName,
			PartId: user.PartId, Email: user.Email, FirstName: user.FirstName, LastName: user.LastName, Department: user.Department, UserGroup: user.UserGroup,
			Hash: user.Hash, CreatedAt: user.CreatedAt, Enabled: user.Enabled}).Error
		if err != nil {
			return err
		}
	}

	return nil

}

// this method deletes user in the database
// it doesn't check internally whether all the validation are applied or not
func (us *UserService) DeleteUser(user *model.TableUser) error {

	// get new instance of user data source
	newUser := model.TableUser{}

	if us.Session.Where("guid =?", user.GUID).Find(&newUser).RecordNotFound() {
		return fmt.Errorf("the user with id '%s' was not found", user.GUID)
	}
	err := us.Session.Debug().Where("guid =?", user.GUID).Delete(&model.TableUser{}).Error
	if err != nil {
		return err
	}
	return nil
}

// this method is used to login the user
// it doesn't check internally whether all the validation are applied or not
func (us *UserService) LoginUser(username, password string) (string, model.TableUser, error) {
	userData := model.TableUser{}

	switch {
	case us.LdapClient != nil:

		ok, isAdmin, user, err := us.LdapClient.Authenticate(username, password)
		if err != nil {
			/* second try after reconnect */
			ok, isAdmin, user, err = us.LdapClient.Authenticate(username, password)
			if err != nil {
				errorString := fmt.Sprintf("Error authenticating user %s: %+v", username, err)
				return "", userData, errors.New(errorString)
			}
		}

		if !ok {
			return "", userData, errors.New("authenticating failed for user")
		}

		userData.UserName = username
		userData.Id = int(hashString(username))
		hash := md5.Sum([]byte(username))
		userData.GUID = hex.EncodeToString(hash[:])
		userData.Password = password
		userData.FirstName = username
		userData.IsAdmin = isAdmin
		userData.ExternalAuth = true
		if val, ok := user["dn"]; ok {
			userData.UserGroup = val
		}

		logger.Debug("LDAP Auth: user: ", userData.UserName, " userID: ", userData.Id, " UserGUID: ", userData.GUID)

		userid := username

		// Microsoft AD implementations require DN for 1.2.840.113556.1.4.1941 recursive group query
		if us.LdapClient.UseDNForGroupSearch {
			userid = user["dn"]
		}

		groups, err := us.LdapClient.GetGroupsOfUser(userid)
		//fmt.Println("LDAP returned groups: ", groups)

		if err != nil {
			logger.Error("Couldn't get any group for user ", username, ": ", err)
			if !us.LdapClient.UserMode && !us.LdapClient.AdminMode {
				return "", userData, errors.New("couldn't fetch any LDAP group and membership is required for login")
			}
		} else {
			logger.Debug("Found groups for user ", username, ": ", groups)
			// ElementExists returns true if the given slice is empty, so we explicitly check that here
			// to prevent users with no groups from becoming admins
			if len(groups) > 0 && heputils.ElementExists(groups, us.LdapClient.AdminGroup) {
				logger.Debug("User ", username, " is a member of the admin group ", us.LdapClient.AdminGroup)
				userData.IsAdmin = true
			} else if len(groups) > 0 && heputils.ElementExists(groups, us.LdapClient.UserGroup) {
				logger.Debug("User ", username, " is a member of the user group ", us.LdapClient.UserGroup)
				userData.IsAdmin = false
			} else {
				if !userData.IsAdmin && us.LdapClient.UserMode {
					logger.Debug("User ", username, " didn't match any group but still logged in as USER because UserMode is set to true.")
					userData.UserGroup = "user"
				}
				if userData.IsAdmin {
					logger.Debug("User ", username, " didn't match any group but still logged in as ADMIN because AdminMode is set to true.")
					userData.UserGroup = "admin"
				}
				if !userData.IsAdmin && !us.LdapClient.UserMode {
					return "", userData, errors.New("failed group match. Group membership is required for login because AdminMode and UserMode are false")
				}
				// thank you nttrandbao for the report and patch
				userData.Enabled = true
			}
		}
	case us.HttpAuth != nil:
		response, err := us.HttpAuth.Authenticate(username, password)
		if err != nil {
			return "", userData, errors.New("password is not correct")
		}
		if !response.Auth {
			return "", userData, errors.New("password is not correct")
		}
		userData = response.Data
		userData.IsAdmin = false
		userData.ExternalAuth = false
		if userData.UserGroup != "" && strings.Contains(strings.ToLower(userData.UserGroup), "admin") {
			userData.IsAdmin = true
		}
	default:
		if err := us.Session.Debug().Table("users").Where("username =?", username).Find(&userData).Error; err != nil {
			return "", userData, errors.New("user is not found")
		}
		if err := bcrypt.CompareHashAndPassword([]byte(userData.Hash), []byte(password)); err != nil {
			return "", userData, errors.New("password is not correct")
		}

		/* check admin or not */
		userData.IsAdmin = false
		userData.ExternalAuth = false
		if userData.UserGroup != "" && strings.Contains(strings.ToLower(userData.UserGroup), "admin") {
			userData.IsAdmin = true
		}
	}

	if config.Setting.MAIN_SETTINGS.EnableGravatar && userData.Email != "" {
		hash := md5.Sum([]byte(userData.Email))
		userData.Avatar = fmt.Sprintf(config.Setting.MAIN_SETTINGS.GravatarUrl, hex.EncodeToString(hash[:]))
	}

	token, err := auth.Token(userData)
	return token, userData, err
}

func hashString(s string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(s))
	return h.Sum32()
}

// this method gets all users from database
func (us *UserService) GetAuthTypeList() ([]byte, error) {

	var userGlobalSettings = model.TableGlobalSettings{}

	replyFinal := gabs.New()

	replyInternal := gabs.New()
	replyInternal.Set("Internal", "name")
	replyInternal.Set("internal", "type")
	replyInternal.Set(1, "position")

	if config.Setting.MAIN_SETTINGS.DefaultAuth == "internal" {
		replyInternal.Set(true, "enable")
	} else {
		replyInternal.Set(false, "enable")
	}

	replyLdap := gabs.New()
	replyLdap.Set("LDAP", "name")
	replyLdap.Set("ldap", "type")
	replyLdap.Set(2, "position")

	if config.Setting.MAIN_SETTINGS.DefaultAuth == "ldap" {
		replyLdap.Set(true, "enable")
	} else {
		replyLdap.Set(false, "enable")
	}

	if config.Setting.OAUTH2_SETTINGS.Enable {
		replyOauth := gabs.New()
		replyOauth.Set(config.Setting.OAUTH2_SETTINGS.ProjectID, "name")
		replyOauth.Set(config.Setting.OAUTH2_SETTINGS.ServiceProviderName, "provider_name")
		replyOauth.Set(config.Setting.OAUTH2_SETTINGS.UrlToServiceRedirect+"/"+config.Setting.OAUTH2_SETTINGS.ServiceProviderName, "url")
		replyOauth.Set(config.Setting.OAUTH2_SETTINGS.ServiceProviderImage, "provider_image")
		replyOauth.Set(config.Setting.OAUTH2_SETTINGS.EnableAutoRedirect, "auto_redirect")
		replyOauth.Set("oauth2", "type")
		replyOauth.Set(3, "position")
		replyOauth.Set(true, "enable")
		replyFinal.ArrayAppend(replyOauth.Data(), "oauth2")
	}

	replyFinal.Set(replyInternal.Data(), "internal")
	replyFinal.Set(replyLdap.Data(), "ldap")

	userGlobalSettings = model.TableGlobalSettings{
		Id:         1,
		GUID:       heputils.GenereateNewUUID(),
		PartId:     10,
		Category:   "system",
		Param:      "authtypes",
		Data:       json.RawMessage(replyFinal.String()),
		CreateDate: time.Now(),
	}

	oj := model.SuccessfulResponse{}
	oj.Data = userGlobalSettings.Data
	oj.Count = 1
	oj.Message = "all good"

	return json.Marshal(oj)
}

func (us *UserService) LoginUserUsingOauthToken(oAuth2Object model.OAuth2MapToken) (string, model.TableUser, error) {

	userJsonData, _ := gabs.ParseJSON(oAuth2Object.ProfileJson)

	userData := model.TableUser{}

	logger.Debug("LoginUserUsingOauthToken json profile: ", string(oAuth2Object.ProfileJson))

	userData.UserGroup = "user"
	userData.IsAdmin = false
	userData.Enabled = true

	if userJsonData.Exists("email") {
		userData.Email = userJsonData.S("email").Data().(string)
		userData.UserName = userData.Email
		userData.Id = int(hashString(userData.UserName))
	}

	// Keycloak returns preferred_username; use it if email is absent
	if userJsonData.Exists("preferred_username") {
		preferredUsername := userJsonData.S("preferred_username").Data().(string)
		if userData.UserName == "" {
			userData.UserName = preferredUsername
			userData.Id = int(hashString(userData.UserName))
		}
	}

	if userJsonData.Exists("family_name") {
		userData.LastName = userJsonData.S("family_name").Data().(string)
	}

	if userJsonData.Exists("given_name") {
		userData.FirstName = userJsonData.S("given_name").Data().(string)
	}

	if userJsonData.Exists("picture") {
		userData.Avatar = userJsonData.S("picture").Data().(string)
	}

	// --- Group / role resolution (Keycloak OIDC) ---
	groupClaimName := config.Setting.OAUTH2_SETTINGS.GroupClaimName
	if groupClaimName == "" {
		groupClaimName = "groups"
	}

	fmt.Println("====== OAUTH2 RBAC DEBUG: CONFIG VALUES ======")
	fmt.Printf("  group_claim_name          = %q\n", groupClaimName)
	fmt.Printf("  admin_group               = %q\n", config.Setting.OAUTH2_SETTINGS.AdminGroup)
	fmt.Printf("  user_group                = %q\n", config.Setting.OAUTH2_SETTINGS.UserGroup)
	fmt.Printf("  extract_groups_from_token = %v\n", config.Setting.OAUTH2_SETTINGS.ExtractGroupsFromToken)

	fmt.Println("====== OAUTH2 RBAC DEBUG: CHECKING USERINFO PROFILE ======")
	fmt.Printf("  claim %q exists (gabs.Exists) = %v\n", groupClaimName, userJsonData.Exists(groupClaimName))
	pathNode := userJsonData.Path(groupClaimName)
	if pathNode != nil && pathNode.Data() != nil {
		fmt.Printf("  claim %q raw value (gabs.Path) = %v\n", groupClaimName, pathNode.Data())
		fmt.Printf("  claim %q raw Go type           = %T\n", groupClaimName, pathNode.Data())
	} else {
		fmt.Printf("  claim %q NOT FOUND via gabs.Path()\n", groupClaimName)
	}

	groupsResolved := false

	// 1. Try the userinfo profile response (returned by profile_url)
	groups := extractGroupsFromContainer(userJsonData, groupClaimName)
	fmt.Printf("  >> Tier 1 result: extracted groups = %v (count=%d)\n", groups, len(groups))
	if len(groups) > 0 {
		groupsResolved = mapGroupsToRole(&userData, groups)
		fmt.Printf("  >> Tier 1 mapGroupsToRole returned = %v\n", groupsResolved)
	}

	// 2. Decode the ID token or access token JWT if configured
	if !groupsResolved && config.Setting.OAUTH2_SETTINGS.ExtractGroupsFromToken {
		fmt.Println("====== OAUTH2 RBAC DEBUG: CHECKING JWT TOKEN ======")
		tokenToCheck := oAuth2Object.IDTokenRaw
		tokenSource := "id_token"
		if tokenToCheck == "" && oAuth2Object.Oauth2Token != nil {
			tokenToCheck = oAuth2Object.Oauth2Token.AccessToken
			tokenSource = "access_token"
		}
		if tokenToCheck == "" {
			fmt.Println("  >> Tier 2: NO token available to decode")
		} else {
			fmt.Printf("  >> Tier 2: decoding %s (first 50 chars: %.50s...)\n", tokenSource, tokenToCheck)
			groups = extractGroupsFromJWT(tokenToCheck, groupClaimName)
			fmt.Printf("  >> Tier 2 result: extracted groups = %v (count=%d)\n", groups, len(groups))
			if len(groups) > 0 {
				groupsResolved = mapGroupsToRole(&userData, groups)
				fmt.Printf("  >> Tier 2 mapGroupsToRole returned = %v\n", groupsResolved)
			}
		}
	} else if !groupsResolved {
		fmt.Println("  >> Tier 2 SKIPPED: extract_groups_from_token is false")
	}

	// 3. Fall back to database lookup by email
	if !groupsResolved && userData.Email != "" {
		fmt.Println("====== OAUTH2 RBAC DEBUG: DATABASE FALLBACK ======")
		isAdmin, _ := us.IsAdmin(userData.Email)
		if isAdmin {
			userData.UserGroup = "admin"
			userData.IsAdmin = true
		}
		fmt.Printf("  >> Tier 3: database lookup for email=%q -> isAdmin=%v\n", userData.Email, isAdmin)
	}

	fmt.Println("====== OAUTH2 RBAC DEBUG: FINAL RESULT ======")
	fmt.Printf("  UserName  = %q\n", userData.UserName)
	fmt.Printf("  UserGroup = %q\n", userData.UserGroup)
	fmt.Printf("  IsAdmin   = %v\n", userData.IsAdmin)
	fmt.Println("===============================================")

	if config.Setting.OAUTH2_SETTINGS.EnableGravatar && userData.Email != "" {
		hash := md5.Sum([]byte(userData.Email))
		userData.Avatar = fmt.Sprintf(config.Setting.OAUTH2_SETTINGS.GravatarUrl, hex.EncodeToString(hash[:]))
	}

	if userJsonData.Exists("id") {
		s := (userJsonData.S("id").Data().(string))
		i, err := strconv.Atoi(s)
		if err == nil {
			userData.Id = i
		} else {
			logger.Error("bad ID size: ", s, i)
		}
	}

	// Keycloak uses "sub" (UUID) instead of numeric "id"
	if userJsonData.Exists("sub") && !userJsonData.Exists("id") {
		if userData.Id == 0 {
			sub := userJsonData.S("sub").Data().(string)
			userData.Id = int(hashString(sub))
		}
	}

	hash := md5.Sum([]byte(userData.UserName))
	userData.GUID = hex.EncodeToString(hash[:])
	userData.ExternalAuth = true

	token, err := auth.Token(userData)
	return token, userData, err
}

// extractGroupsFromContainer reads a string array from a gabs container using
// a dotted path (e.g. "groups" or "realm_access.roles").
func extractGroupsFromContainer(container *gabs.Container, claimPath string) []string {
	node := container.Path(claimPath)
	if node == nil || node.Data() == nil {
		return nil
	}
	children := node.Children()
	if len(children) == 0 {
		if s, ok := node.Data().(string); ok {
			return []string{s}
		}
		return nil
	}
	var groups []string
	for _, child := range children {
		if g, ok := child.Data().(string); ok {
			groups = append(groups, g)
		}
	}
	return groups
}

// extractGroupsFromJWT base64-decodes a JWT payload (no signature verification
// -- the token was already validated during the OAuth2 exchange) and pulls
// the groups array from the claims.
func extractGroupsFromJWT(tokenString, claimPath string) []string {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		logger.Error("extractGroupsFromJWT: base64 decode failed: ", err.Error())
		return nil
	}
	container, err := gabs.ParseJSON(payload)
	if err != nil {
		logger.Error("extractGroupsFromJWT: JSON parse failed: ", err.Error())
		return nil
	}
	return extractGroupsFromContainer(container, claimPath)
}

// groupMatches handles Keycloak path-based groups (e.g. "/homer-admin")
// as well as simple group names ("admin").
func groupMatches(keycloakGroup, configuredGroup string) bool {
	kg := strings.ToLower(strings.TrimSpace(keycloakGroup))
	cg := strings.ToLower(strings.TrimSpace(configuredGroup))

	if kg == cg {
		return true
	}

	kgTrimmed := strings.Trim(kg, "/")
	cgTrimmed := strings.Trim(cg, "/")

	if kgTrimmed == cgTrimmed {
		return true
	}

	// "/parent/homer-admin" should match "homer-admin"
	if idx := strings.LastIndex(kgTrimmed, "/"); idx >= 0 {
		if kgTrimmed[idx+1:] == cgTrimmed {
			return true
		}
	}
	return false
}

// mapGroupsToRole checks the supplied groups against the configured admin and
// user group names and sets the corresponding role on userData.
func mapGroupsToRole(userData *model.TableUser, groups []string) bool {
	adminGroup := config.Setting.OAUTH2_SETTINGS.AdminGroup
	userGroup := config.Setting.OAUTH2_SETTINGS.UserGroup
	if adminGroup == "" {
		adminGroup = "admin"
	}
	if userGroup == "" {
		userGroup = "user"
	}

	fmt.Printf("  mapGroupsToRole: checking %d groups against admin=%q user=%q\n", len(groups), adminGroup, userGroup)

	for _, g := range groups {
		match := groupMatches(g, adminGroup)
		fmt.Printf("    groupMatches(%q, adminGroup=%q) -> %v\n", g, adminGroup, match)
		if match {
			userData.IsAdmin = true
			userData.UserGroup = "admin"
			return true
		}
	}

	for _, g := range groups {
		match := groupMatches(g, userGroup)
		fmt.Printf("    groupMatches(%q, userGroup=%q) -> %v\n", g, userGroup, match)
		if match {
			userData.IsAdmin = false
			userData.UserGroup = "user"
			return true
		}
	}

	fmt.Printf("  mapGroupsToRole: NO MATCH for any group in %v\n", groups)
	return false
}

// this method gets all users from database
/*func (us *UserService) GetUserFromToken(userTokenProfile *auth.JwtUserClaim) (model.TableUser, error) {

	userProfile := model.TableUser{}

	userProfile.Id = 0
	userProfile.UserName = userTokenProfile.UserName
	userProfile.UserGroup = userTokenProfile.UserGroup
	userProfile.Email = userTokenProfile.ExternalProfile
	userProfile.LastName = userTokenProfile.DisplayName
	userProfile.Avatar = userTokenProfile.Avatar
	userProfile.IsAdmin = userTokenProfile.UserAdmin
	userProfile.ExternalAuth = userTokenProfile.ExternalAuth
	userProfile.ExternalProfile = userTokenProfile.ExternalProfile

	return userProfile, nil
}
*/

/* get all */
func (us *UserService) GetUserProfileFromToken(userTokenProfile *auth.JwtUserClaim) (string, error) {

	userProfile := model.UserProfile{}
	userProfile.UserName = userTokenProfile.UserName
	userProfile.UserGroup = userTokenProfile.UserGroup
	userProfile.ExternalAuth = userTokenProfile.ExternalAuth
	userProfile.DisplayName = userTokenProfile.DisplayName
	userProfile.Avatar = userTokenProfile.Avatar
	userProfile.UserAdmin = userTokenProfile.UserAdmin

	userProfile.ExternalProfile = userTokenProfile.ExternalProfile

	if !userTokenProfile.ExternalAuth {
		user, count, err := us.GetUser(userTokenProfile.UserName, false)
		if err == nil && count > 0 {
			userProfile.GUID = user[0].GUID
		}
	}

	data, _ := json.Marshal(userProfile)
	rows, _ := gabs.ParseJSON(data)
	count, _ := rows.ArrayCount()

	reply := gabs.New()
	reply.Set(count, "count")
	reply.Set(rows.Data(), "data")
	return reply.String(), nil
}
