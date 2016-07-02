using System;
using System.Linq;
using System.Web.Security;
using MailManager.MailContext;

namespace MailManager.Core
{
    public class CustomRoleProvider : RoleProvider
    {
        private MailManagerDb db = new MailManagerDb();
        public override bool IsUserInRole(string username, string roleName)
        {

            var user = db.UsersInRoles.Where(u => u.User.UserName == username && u.tbl_Role.Role == roleName).ToList();
            if (user == null)
                return false;
            return true;
        }
        //[CustomAuthorize]
        public override string[] GetRolesForUser(string username)
        {

            var user = db.Users.Where(u => u.UserName == username).FirstOrDefault();
            if (user == null)
            {
                return new string[] { };
            }

            return user.UsersInRoles == null ? new string[] { } : user.UsersInRoles.Select(u => u.tbl_Role).Select(u => u.Role).ToArray();

        }

        public override void CreateRole(string roleName)
        {
            throw new NotImplementedException();
        }

        public override bool DeleteRole(string roleName, bool throwOnPopulatedRole)
        {
            throw new NotImplementedException();
        }

        public override bool RoleExists(string roleName)
        {
            throw new NotImplementedException();
        }

        public override void AddUsersToRoles(string[] usernames, string[] roleNames)
        {
            throw new NotImplementedException();
        }

        public override void RemoveUsersFromRoles(string[] usernames, string[] roleNames)
        {
            throw new NotImplementedException();
        }

        public override string[] GetUsersInRole(string roleName)
        {
            throw new NotImplementedException();
        }

        public override string[] GetAllRoles()
        {
           return db.tbl_Role.Select(r => r.Role).ToArray();
        }

        public override string[] FindUsersInRole(string roleName, string usernameToMatch)
        {
            throw new NotImplementedException();
        }

        public override string ApplicationName { get; set; }
    }
}