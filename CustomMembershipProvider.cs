using System;
using System.Security.Cryptography;
using System.Text;
using System.Web.Security;
using System.Linq;
using MailManager.MailContext;

namespace MailManager.Core
{
    public class CustomMembershipProvider : MembershipProvider
    {
        private MailManagerDb db = new MailManagerDb();
        public override string ApplicationName
        {
            get;
            set;
        }

        public override bool ChangePassword(string username, string oldPassword, string newPassword)
        {
            string pass = GetMd5Hash(oldPassword);
            var userObj = db.Users.Where(w => w.UserName == username && w.Password == pass).FirstOrDefault();
            if (userObj == null)
            {
                return false;
            }
            userObj.Password = GetMd5Hash(newPassword);

            db.Users.Attach(userObj);
            var entry = db.Entry(userObj);
            entry.Property(x => x.Password).IsModified = true;
            db.SaveChanges();
            return true;

        }

        public override bool ChangePasswordQuestionAndAnswer(string username, string password, string newPasswordQuestion, string newPasswordAnswer)
        {
            throw new NotImplementedException();
        }

        public override MembershipUser CreateUser(string username, string password, string email, string passwordQuestion, string passwordAnswer, bool isApproved, object providerUserKey, out MembershipCreateStatus status)
        {
            var args = new ValidatePasswordEventArgs(username, password, true);
            OnValidatingPassword(args);

            if (args.Cancel)
            {
                status = MembershipCreateStatus.InvalidPassword;
                return null;
            }

            if (GetUserNameByEmail(email) != string.Empty)
            {
                status = MembershipCreateStatus.DuplicateEmail;
                return null;
            }

            var user = GetUser(username, true);

            if (user == null)
            {
                User userObj = new User { UserName = username, Password = GetMd5Hash(password), Email = email };
                db.Users.Add(userObj);
                db.SaveChanges();

                status = MembershipCreateStatus.Success;

                return GetUser(username, true);
            }
            status = MembershipCreateStatus.DuplicateUserName;

            return null;
        }

        public override bool DeleteUser(string username, bool deleteAllRelatedData)
        {
            var user = db.Users.Where(u => u.UserName == username).FirstOrDefault();

            if (user == null)
            {
                return false;
            }

            //update userRole table after deleting user
            var userRole = db.UsersInRoles.Where(r => r.UserId == user.UserId).ToList();
            foreach (var ur in userRole)
            {
                db.UsersInRoles.Remove(ur);
                db.SaveChanges();
            }
            db.Users.Remove(user);
            db.SaveChanges();
             
           
            return true;
        }

        public override bool EnablePasswordReset
        {
            get { return true; }
        }

        public override bool EnablePasswordRetrieval
        {
            get { return true; }
        }

        public override MembershipUserCollection FindUsersByEmail(string emailToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            throw new NotImplementedException();
        }

        public override MembershipUserCollection FindUsersByName(string usernameToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            throw new NotImplementedException();
        }

        public override MembershipUserCollection GetAllUsers(int pageIndex, int pageSize, out int totalRecords)
        {
            throw new NotImplementedException();
        }

        public override int GetNumberOfUsersOnline()
        {
            throw new NotImplementedException();
        }

        public override string GetPassword(string username, string answer)
        {
            throw new NotImplementedException();
        }

        public override MembershipUser GetUser(string username, bool userIsOnline)
        {
            var user = db.Users.Where(u => u.UserName == username).FirstOrDefault();
            if (user != null && !string.IsNullOrEmpty(user.UserName))
            {
                var memUser = new MembershipUser("CustomMembershipProvider", username, user.UserId, user.Email,
                                                            string.Empty, string.Empty,
                                                            true, false, DateTime.MinValue,
                                                            DateTime.MinValue,
                                                            DateTime.MinValue,
                                                            DateTime.Now, DateTime.Now);
                return memUser;
            }
            return null;

        }

        public override MembershipUser GetUser(object providerUserKey, bool userIsOnline)
        {
            throw new NotImplementedException();
        }

        public override string GetUserNameByEmail(string email)
        {
            var user = db.Users.Where(u => u.Email == email).FirstOrDefault();
            if (user == null)
            {
                return string.Empty;
            }
            return email;
        }

        public override int MaxInvalidPasswordAttempts
        {
            get { return 0; }
        }

        public override int MinRequiredNonAlphanumericCharacters
        {
            get { return 0; }
        }

        public override int MinRequiredPasswordLength
        {
            get { return 6; }
        }

        public override int PasswordAttemptWindow
        {
            get { throw new NotImplementedException(); }
        }

        public override MembershipPasswordFormat PasswordFormat
        {
            get { throw new NotImplementedException(); }
        }

        public override string PasswordStrengthRegularExpression
        {
            get { throw new NotImplementedException(); }
        }

        public override bool RequiresQuestionAndAnswer
        {
            get { throw new NotImplementedException(); }
        }

        public override bool RequiresUniqueEmail
        {
            get { return false; }
        }

        public override string ResetPassword(string username, string answer)
        {
            throw new NotImplementedException();
        }

        public override bool UnlockUser(string userName)
        {
            throw new NotImplementedException();
        }

        public override void UpdateUser(MembershipUser user)
        {
            throw new NotImplementedException();
        }

        public override bool ValidateUser(string username, string password)
        {
            var md5Hash = GetMd5Hash(password);
            MailManagerDb db = new MailManagerDb();
            var users = db.Users.Where(u => u.UserName == username && u.Password == md5Hash).ToList();// (u => u.UserName == username && u.Password == password);
            return users.Count > 0;
        }
        public static string GetMd5Hash(string value)
        {
            var md5Hasher = MD5.Create();
            var data = md5Hasher.ComputeHash(Encoding.Default.GetBytes(value));
            var sBuilder = new StringBuilder();
            for (var i = 0; i < data.Length; i++)
            {
                sBuilder.Append(data[i].ToString("x2"));
            }
            return sBuilder.ToString();

        }
    }
}



