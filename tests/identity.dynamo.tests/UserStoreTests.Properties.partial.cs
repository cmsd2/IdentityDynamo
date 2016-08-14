// MIT License Copyright 2014 (c) David Melendez. All rights reserved. See License.txt in the project root for license information.
using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using ElCamino.AspNet.Identity.Dynamo;
using System.Collections.Generic;
using System.Security.Claims;
using System.Linq;
using System.Threading;
using ElCamino.AspNet.Identity.Dynamo.Model;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace ElCamino.AspNet.Identity.Dynamo.Tests
{
    public partial class UserStoreTests
    {
        [TestMethod]
        [TestCategory("Identity.Dynamo.UserStore.Properties")]
        public void AccessFailedCount()
        {
            IdentityOptions identityOptions = new IdentityOptions {Lockout = {MaxFailedAccessAttempts = 2}};
            IOptions<IdentityOptions> options = Options.Create(identityOptions);

            using (UserStore<IdentityUser> store = new UserStore<IdentityUser>(loggerFactory, new IdentityCloudContext<IdentityUser>()))
            {
                using (UserManager<IdentityUser> manager = new UserManager<IdentityUser>(store, options, new PasswordHasher<IdentityUser>(), null, null, lookupNormalizer, new IdentityErrorDescriber(), null, loggerFactory.CreateLogger<UserManager<IdentityUser>>()))
                {
                    var user = CreateTestUser();
                    var taskUser = manager.GetAccessFailedCountAsync(user);
                    taskUser.Wait();
                    Assert.AreEqual<int>(user.AccessFailedCount, taskUser.Result, "AccessFailedCount not equal");

                    var taskAccessFailed = manager.AccessFailedAsync(user);
                    taskAccessFailed.Wait();
                    Assert.IsTrue(taskAccessFailed.Result.Succeeded, string.Concat(taskAccessFailed.Result.Errors));

                    var taskUser2 = manager.FindByIdAsync(user.Id);
                    user = taskUser2.Result;
                    var taskAccessReset = manager.ResetAccessFailedCountAsync(user);
                    taskAccessReset.Wait();
                    Assert.IsTrue(taskAccessReset.Result.Succeeded, string.Concat(taskAccessReset.Result.Errors));

                    try
                    {
                        var task = store.GetAccessFailedCountAsync(null, CancellationToken.None);
                        task.Wait();
                    }
                    catch (Exception ex)
                    {
                        Assert.IsNotNull(ex, "Argument exception not raised");
                    }

                    try
                    {
                        var task = store.IncrementAccessFailedCountAsync(null, CancellationToken.None);
                        task.Wait();
                    }
                    catch (Exception ex)
                    {
                        Assert.IsNotNull(ex, "Argument exception not raised");
                    }

                    try
                    {
                        var task = store.ResetAccessFailedCountAsync(null, CancellationToken.None);
                        task.Wait();
                    }
                    catch (Exception ex)
                    {
                        Assert.IsNotNull(ex, "Argument exception not raised");
                    }

                }
            }
        }

        private void SetValidateEmail(UserManager<IdentityUser> manager,
            UserStore<IdentityUser> store,
            IdentityUser user,
            string strNewEmail)
        {
            string originalEmail = user.Email;
            var taskUserSet = manager.SetEmailAsync(user, strNewEmail);
            taskUserSet.Wait();
            Assert.IsTrue(taskUserSet.Result.Succeeded, string.Concat(taskUserSet.Result.Errors));

            var taskUser = manager.GetEmailAsync(user);
            taskUser.Wait();
            if (!string.IsNullOrWhiteSpace(strNewEmail))
            {
                Assert.AreEqual<string>(strNewEmail, taskUser.Result, "GetEmailAsync: Email not equal");
            }
            else
            {
                Assert.IsNull(taskUser.Result, "GetEmailAsync: Email not null");
            }
            if (!string.IsNullOrWhiteSpace(strNewEmail))
            {
                TestContext.WriteLine("New email: {0}", strNewEmail);
                var taskFind = manager.FindByEmailAsync(strNewEmail);
                taskFind.Wait();
                WriteLineObject<IdentityUser>(taskFind.Result);
                Assert.AreEqual<string>(strNewEmail, taskFind.Result.Email, "FindByEmailAsync: Email not equal");
            }
            
            //Should not find old by old email.
            if (!string.IsNullOrWhiteSpace(originalEmail))
            {
                TestContext.WriteLine("Original email: {0}", originalEmail);
                var taskFind = manager.FindByEmailAsync(originalEmail);
                taskFind.Wait();
                if (taskFind.Result != null)
                {
                    WriteLineObject<IdentityUser>(taskFind.Result);
                }
                Assert.IsNull(taskFind.Result, "FindByEmailAsync: Old email should not yield a find result.");
            }

        }

        [TestMethod]
        [TestCategory("Identity.Dynamo.UserStore.Properties")]
        public void EmailNone()
        {
            using (UserStore<IdentityUser> store = new UserStore<IdentityUser>(loggerFactory, new IdentityCloudContext<IdentityUser>()))
            {
                using (UserManager<IdentityUser> manager = new UserManager<IdentityUser>(store, null, new PasswordHasher<IdentityUser>(), null, null, lookupNormalizer, new IdentityErrorDescriber(), null, loggerFactory.CreateLogger<UserManager<IdentityUser>>()))
                {
                    var user = CreateTestUser(false, false);
                    string strNewEmail = string.Format("{0}@hotmail.com", Guid.NewGuid().ToString("N"));
                    SetValidateEmail(manager, store, user, strNewEmail);

                    SetValidateEmail(manager, store, user, string.Empty);

                }
            }
        }

        [TestMethod]
        [TestCategory("Identity.Dynamo.UserStore.Properties")]
        public void Email()
        {
            using (UserStore<IdentityUser> store = new UserStore<IdentityUser>(loggerFactory, new IdentityCloudContext<IdentityUser>()))
            {
                using (UserManager<IdentityUser> manager = new UserManager<IdentityUser>(store, null, new PasswordHasher<IdentityUser>(), null, null, lookupNormalizer, new IdentityErrorDescriber(), null, loggerFactory.CreateLogger<UserManager<IdentityUser>>()))
                {
                    var user = CreateTestUser(true, true, string.Format("{0}@mydomain.com", Guid.NewGuid().ToString("N")));

                    string strNewEmail = string.Format("{0}@gmail.com", Guid.NewGuid().ToString("N"));
                    SetValidateEmail(manager, store, user, strNewEmail);

                    try
                    {
                        var task = store.GetEmailAsync(null, CancellationToken.None);
                        task.Wait();
                    }
                    catch (Exception ex)
                    {
                        Assert.IsNotNull(ex, "Argument exception not raised");
                    }

                    try
                    {
                        var task = store.SetEmailAsync(null, strNewEmail, CancellationToken.None);
                        task.Wait();
                    }
                    catch (Exception ex)
                    {
                        Assert.IsNotNull(ex, "Argument exception not raised");
                    }

                    try
                    {
                        var task = store.SetEmailAsync(user, null, CancellationToken.None);
                        task.Wait();
                    }
                    catch (Exception ex)
                    {
                        Assert.IsNotNull(ex, "Argument exception not raised");
                    }
                }
            }
        }


        [TestMethod]
        [TestCategory("Identity.Dynamo.UserStore.Properties")]
        public void EmailConfirmed()
        {
            using (UserStore<IdentityUser> store = new UserStore<IdentityUser>(loggerFactory, new IdentityCloudContext<IdentityUser>()))
            {
                using (UserManager<IdentityUser> manager = new UserManager<IdentityUser>(store, null, new PasswordHasher<IdentityUser>(), null, null, lookupNormalizer, new IdentityErrorDescriber(), null, loggerFactory.CreateLogger<UserManager<IdentityUser>>()))
                {
                    manager.RegisterTokenProvider("email-token-provider", new EmailTokenProvider<IdentityUser>());
                    var user = CreateTestUser();

                    var taskUserSet = manager.GenerateEmailConfirmationTokenAsync(user);
                    taskUserSet.Wait();
                    Assert.IsFalse(string.IsNullOrWhiteSpace(taskUserSet.Result), "GenerateEmailConfirmationToken failed.");
                    string token = taskUserSet.Result;

                    var taskConfirm = manager.ConfirmEmailAsync(user, token);
                    taskConfirm.Wait();
                    Assert.IsTrue(taskConfirm.Result.Succeeded, string.Concat(taskConfirm.Result.Errors));

                    user = manager.FindByEmailAsync(user.Email).Result;
                    var taskConfirmGet = store.GetEmailConfirmedAsync(user, CancellationToken.None);
                    taskConfirmGet.Wait();
                    Assert.IsTrue(taskConfirmGet.Result, "Email not confirmed");

                    try
                    {
                        var task = store.SetEmailConfirmedAsync(null, true, CancellationToken.None);
                        task.Wait();
                    }
                    catch (Exception ex)
                    {
                        Assert.IsNotNull(ex, "Argument exception not raised");
                    }

                    try
                    {
                        var task = store.GetEmailConfirmedAsync(null, CancellationToken.None);
                        task.Wait();
                    }
                    catch (Exception ex)
                    {
                        Assert.IsNotNull(ex, "Argument exception not raised");
                    }

                }
            }
        }

        [TestMethod]
        [TestCategory("Identity.Dynamo.UserStore.Properties")]
        public void LockoutEnabled()
        {
            using (UserStore<IdentityUser> store = new UserStore<IdentityUser>(loggerFactory, new IdentityCloudContext<IdentityUser>()))
            {
                using (UserManager<IdentityUser> manager = new UserManager<IdentityUser>(store, null, new PasswordHasher<IdentityUser>(), null, null, lookupNormalizer, new IdentityErrorDescriber(), null, loggerFactory.CreateLogger<UserManager<IdentityUser>>()))
                {
                    manager.RegisterTokenProvider("email-token-provider", new EmailTokenProvider<IdentityUser>());

                    var user = User;

                    var taskLockoutSet = manager.SetLockoutEnabledAsync(user, true);
                    taskLockoutSet.Wait();
                    Assert.IsTrue(taskLockoutSet.Result.Succeeded, string.Concat(taskLockoutSet.Result.Errors));

                    DateTimeOffset offSet = new DateTimeOffset(DateTime.UtcNow.AddMinutes(3));
                    var taskDateSet = manager.SetLockoutEndDateAsync(user, offSet);
                    taskDateSet.Wait();
                    Assert.IsTrue(taskDateSet.Result.Succeeded, string.Concat(taskDateSet.Result.Errors));

                    var taskEnabledGet = manager.GetLockoutEnabledAsync(user);
                    taskEnabledGet.Wait();
                    Assert.IsTrue(taskEnabledGet.Result, "Lockout not true");

                    var taskDateGet = manager.GetLockoutEndDateAsync(user);
                    taskDateGet.Wait();
                    //The DateTimeOffSet is off by ~ 2ticks
                    Assert.AreEqual(offSet.Date.ToShortDateString(), taskDateGet.Result.Value.Date.ToShortDateString(), "Lockout date incorrect");

                    DateTime tmpDate = DateTime.UtcNow.AddDays(1);
                    user.LockoutEndDateUtc = tmpDate;
                    var taskGet = store.GetLockoutEndDateAsync(user, CancellationToken.None);
                    taskGet.Wait();
                    Assert.AreEqual<DateTimeOffset>(new DateTimeOffset(tmpDate), taskGet.Result.Value, "LockoutEndDate not set");

                    user.LockoutEndDateUtc = null;
                    var taskGet2 = store.GetLockoutEndDateAsync(user, CancellationToken.None);
                    taskGet2.Wait();
                    Assert.AreEqual<DateTimeOffset>(new DateTimeOffset(), taskGet2.Result.Value, "LockoutEndDate not set");

                    var minOffSet = DateTimeOffset.MinValue;
                    var taskSet2 = store.SetLockoutEndDateAsync(user, minOffSet, CancellationToken.None);
                    taskSet2.Wait();
                    Assert.IsNull(user.LockoutEndDateUtc, "LockoutEndDate not null");


                    try
                    {
                        store.GetLockoutEnabledAsync(null, CancellationToken.None);
                    }
                    catch (ArgumentException) { }


                    try
                    {
                        store.GetLockoutEndDateAsync(null, CancellationToken.None);
                    }
                    catch (ArgumentException) { }

                    try
                    {
                        store.SetLockoutEndDateAsync(null, offSet, CancellationToken.None);
                    }
                    catch (ArgumentException) { }

                    try
                    {
                        store.SetLockoutEnabledAsync(null, false, CancellationToken.None);
                    }
                    catch (ArgumentException) { }
                }
            }
        }

        [TestMethod]
        [TestCategory("Identity.Dynamo.UserStore.Properties")]
        public void PhoneNumber()
        {
            using (UserStore<IdentityUser> store = new UserStore<IdentityUser>(loggerFactory, new IdentityCloudContext<IdentityUser>()))
            {
                using (UserManager<IdentityUser> manager = new UserManager<IdentityUser>(store, null, new PasswordHasher<IdentityUser>(), null, null, lookupNormalizer, new IdentityErrorDescriber(), null, loggerFactory.CreateLogger<UserManager<IdentityUser>>()))
                {
                    var user = User;

                    string strNewPhoneNumber = "542-887-3434";
                    var taskPhoneNumberSet = manager.SetPhoneNumberAsync(user, strNewPhoneNumber);
                    taskPhoneNumberSet.Wait();
                    Assert.IsTrue(taskPhoneNumberSet.Result.Succeeded, string.Concat(taskPhoneNumberSet.Result.Errors));

                    var taskUser = manager.GetPhoneNumberAsync(user);
                    taskUser.Wait();
                    Assert.AreEqual<string>(strNewPhoneNumber, taskUser.Result, "PhoneNumber not equal");

                    try
                    {
                        var task = store.GetPhoneNumberAsync(null, CancellationToken.None);
                        task.Wait();
                    }
                    catch (Exception ex)
                    {
                        Assert.IsNotNull(ex, "Argument exception not raised");
                    }

                    try
                    {
                        var task = store.SetPhoneNumberAsync(null, strNewPhoneNumber, CancellationToken.None);
                        task.Wait();
                    }
                    catch (Exception ex)
                    {
                        Assert.IsNotNull(ex, "Argument exception not raised");
                    }

                    try
                    {
                        var task = store.SetPhoneNumberAsync(user, null, CancellationToken.None);
                        task.Wait();
                    }
                    catch (Exception ex)
                    {
                        Assert.IsNotNull(ex, "Argument exception not raised");
                    }
                }
            }
        }

        [TestMethod]
        [TestCategory("Identity.Dynamo.UserStore.Properties")]
        public void PhoneNumberConfirmed()
        {
            using (UserStore<IdentityUser> store = new UserStore<IdentityUser>(loggerFactory, new IdentityCloudContext<IdentityUser>()))
            {
                using (UserManager<IdentityUser> manager = new UserManager<IdentityUser>(store, null, new PasswordHasher<IdentityUser>(), null, null, lookupNormalizer, new IdentityErrorDescriber(), null, loggerFactory.CreateLogger<UserManager<IdentityUser>>()))
                {
                    manager.RegisterTokenProvider("phone-number-token-provider",
                        new PhoneNumberTokenProvider<IdentityUser>());
                    var user = CreateTestUser();
                    string strNewPhoneNumber = "425-555-1111";
                    var taskUserSet = manager.GenerateChangePhoneNumberTokenAsync(user, strNewPhoneNumber);
                    taskUserSet.Wait();
                    Assert.IsFalse(string.IsNullOrWhiteSpace(taskUserSet.Result), "GeneratePhoneConfirmationToken failed.");
                    string token = taskUserSet.Result;

                    var taskConfirm = manager.ChangePhoneNumberAsync(user, strNewPhoneNumber, token);
                    taskConfirm.Wait();
                    Assert.IsTrue(taskConfirm.Result.Succeeded, string.Concat(taskConfirm.Result.Errors));

                    user = manager.FindByEmailAsync(user.Email).Result;
                    var taskConfirmGet = store.GetPhoneNumberConfirmedAsync(user, CancellationToken.None);
                    taskConfirmGet.Wait();
                    Assert.IsTrue(taskConfirmGet.Result, "Phone not confirmed");

                    try
                    {
                        var task = store.SetPhoneNumberConfirmedAsync(null, true, CancellationToken.None);
                        task.Wait();
                    }
                    catch (Exception ex)
                    {
                        Assert.IsNotNull(ex, "Argument exception not raised");
                    }

                    try
                    {
                        var task = store.GetPhoneNumberConfirmedAsync(null, CancellationToken.None);
                        task.Wait();
                    }
                    catch (Exception ex)
                    {
                        Assert.IsNotNull(ex, "Argument exception not raised");
                    }

                }
            }
        }

        [TestMethod]
        [TestCategory("Identity.Dynamo.UserStore.Properties")]
        public void TwoFactorEnabled()
        {
            using (UserStore<IdentityUser> store = new UserStore<IdentityUser>(loggerFactory, new IdentityCloudContext<IdentityUser>()))
            {
                using (UserManager<IdentityUser> manager = new UserManager<IdentityUser>(store, null, new PasswordHasher<IdentityUser>(), null, null, lookupNormalizer, new IdentityErrorDescriber(), null, loggerFactory.CreateLogger<UserManager<IdentityUser>>()))
                {
                    var user = User;

                    bool twoFactorEnabled = true;
                    var taskTwoFactorEnabledSet = manager.SetTwoFactorEnabledAsync(user, twoFactorEnabled);
                    taskTwoFactorEnabledSet.Wait();
                    Assert.IsTrue(taskTwoFactorEnabledSet.Result.Succeeded, string.Concat(taskTwoFactorEnabledSet.Result.Errors));

                    var taskUser = manager.GetTwoFactorEnabledAsync(user);
                    taskUser.Wait();
                    Assert.AreEqual<bool>(twoFactorEnabled, taskUser.Result, "TwoFactorEnabled not true");

                    try
                    {
                        var task = store.GetTwoFactorEnabledAsync(null, CancellationToken.None);
                        task.Wait();
                    }
                    catch (Exception ex)
                    {
                        Assert.IsNotNull(ex, "Argument exception not raised");
                    }

                    try
                    {
                        var task = store.SetTwoFactorEnabledAsync(null, twoFactorEnabled, CancellationToken.None);
                        task.Wait();
                    }
                    catch (Exception ex)
                    {
                        Assert.IsNotNull(ex, "Argument exception not raised");
                    }

                }
            }
        }

        [TestMethod]
        [TestCategory("Identity.Dynamo.UserStore.Properties")]
        public void PasswordHash()
        {
            using (UserStore<IdentityUser> store = new UserStore<IdentityUser>(loggerFactory, new IdentityCloudContext<IdentityUser>()))
            {
                var passwordHasher = new PasswordHasher<IdentityUser>();
                using (UserManager<IdentityUser> manager = new UserManager<IdentityUser>(store, null, passwordHasher, null, null, lookupNormalizer, new IdentityErrorDescriber(), null, loggerFactory.CreateLogger<UserManager<IdentityUser>>()))
                {
                    var user = User;
                    string passwordPlain = Guid.NewGuid().ToString("N");
                    string passwordHash = passwordHasher.HashPassword(user, passwordPlain);

                    var taskUserSet = store.SetPasswordHashAsync(user, passwordHash, CancellationToken.None);
                    taskUserSet.Wait();

                    var taskHasHash = manager.HasPasswordAsync(user);
                    taskHasHash.Wait();
                    Assert.IsTrue(taskHasHash.Result, "PasswordHash not set");

                    var taskUser = store.GetPasswordHashAsync(user, CancellationToken.None);
                    taskUser.Wait();
                    Assert.AreEqual<string>(passwordHash, taskUser.Result, "PasswordHash not equal");
                    user.PasswordHash = passwordHash;
                    try
                    {
                        var task = store.GetPasswordHashAsync(null, CancellationToken.None);
                        task.Wait();
                    }
                    catch (Exception ex)
                    {
                        Assert.IsNotNull(ex, "Argument exception not raised");
                    }

                    try
                    {
                        var task = store.HasPasswordAsync(null, CancellationToken.None);
                        task.Wait();
                    }
                    catch (Exception ex)
                    {
                        Assert.IsNotNull(ex, "Argument exception not raised");
                    }

                    try
                    {
                        var task = store.SetPasswordHashAsync(null, passwordHash, CancellationToken.None);
                        task.Wait();
                    }
                    catch (Exception ex)
                    {
                        Assert.IsNotNull(ex, "Argument exception not raised");
                    }

                    try
                    {
                        var task = store.SetPasswordHashAsync(user, null, CancellationToken.None);
                        task.Wait();
                    }
                    catch (Exception ex)
                    {
                        Assert.IsNotNull(ex, "Argument exception not raised");
                    }
                }
            }
        }

        [TestMethod]
        [TestCategory("Identity.Dynamo.UserStore.Properties")]
        public void UsersProperty()
        {
            using (UserStore<IdentityUser> store = new UserStore<IdentityUser>(loggerFactory))
            {
                Assert.IsNull(store.Users, "Users Property is not null");
            }
        }

        [TestMethod]
        [TestCategory("Identity.Dynamo.UserStore.Properties")]
        public void SecurityStamp()
        {
            using (UserStore<IdentityUser> store = new UserStore<IdentityUser>(loggerFactory, new IdentityCloudContext<IdentityUser>()))
            {
                using (UserManager<IdentityUser> manager = new UserManager<IdentityUser>(store, null, new PasswordHasher<IdentityUser>(), null, null, lookupNormalizer, new IdentityErrorDescriber(), null, loggerFactory.CreateLogger<UserManager<IdentityUser>>()))
                {
                    var user = CreateTestUser();

                    var taskUser = manager.GetSecurityStampAsync(user);
                    taskUser.Wait();
                    Assert.AreEqual<string>(user.SecurityStamp, taskUser.Result, "SecurityStamp not equal");

                    string strNewSecurityStamp = Guid.NewGuid().ToString("N");
                    var taskUserSet = store.SetSecurityStampAsync(user, strNewSecurityStamp, CancellationToken.None);
                    taskUserSet.Wait();

                    try
                    {
                        var task = store.GetSecurityStampAsync(null, CancellationToken.None);
                        task.Wait();
                    }
                    catch (Exception ex)
                    {
                        Assert.IsNotNull(ex, "Argument exception not raised");
                    }

                    try
                    {
                        var task = store.SetSecurityStampAsync(null, strNewSecurityStamp, CancellationToken.None);
                        task.Wait();
                    }
                    catch (Exception ex)
                    {
                        Assert.IsNotNull(ex, "Argument exception not raised");
                    }

                    try
                    {
                        var task = store.SetSecurityStampAsync(user, null, CancellationToken.None);
                        task.Wait();
                    }
                    catch (Exception ex)
                    {
                        Assert.IsNotNull(ex, "Argument exception not raised");
                    }
                }
            }
        }

    }
}
