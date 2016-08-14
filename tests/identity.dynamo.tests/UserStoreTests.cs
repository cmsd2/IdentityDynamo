// MIT License Copyright 2014 (c) David Melendez. All rights reserved. See License.txt in the project root for license information.
using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using ElCamino.AspNet.Identity.Dynamo;
using System.Collections.Generic;
using System.Security.Claims;
using System.Linq;
using ElCamino.AspNet.Identity.Dynamo.Model;
using System.Threading;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;

namespace ElCamino.AspNet.Identity.Dynamo.Tests
{
    [TestClass]
    public partial class UserStoreTests
    {
        #region Static and Const Members
        public static string DefaultUserPassword;
        private static IdentityUser User = null;
        private static bool tablesCreated = false;
        private static List<string> NoCreateUserTests =
            new List<string>() { 
                "AddRemoveUserLogin",
                "AddUserLogin",
                "ChangeUserName",
                "CreateUser",
                "DeleteUser",
                "ThrowIfDisposed",
                "UpdateApplicationUser",
                "UpdateUser",
                "UserStoreCtors",
                "AccessFailedCount",
                "EmailConfirmed",
                "EmailNone",
                "PhoneNumberConfirmed",
                "SecurityStamp",
                "UsersProperty",
                "FindUsersByEmail",
                "Email"
                };

        #endregion

        private TestContext testContextInstance;

        private ILoggerFactory loggerFactory;
        private ILookupNormalizer lookupNormalizer;

        public UserStoreTests()
        {
            loggerFactory = new LoggerFactory();
            loggerFactory.AddConsole();
            lookupNormalizer = new UpperInvariantLookupNormalizer();
        }

        /// <summary>
        ///Gets or sets the test context which provides
        ///information about and functionality for the current test run.
        ///</summary>
        public TestContext TestContext
        {
            get
            {
                return testContextInstance;
            }
            set
            {
                testContextInstance = value;
            }
        }


        #region Test Initialization
        [TestInitialize]
        public void Initialize()
        {
            DefaultUserPassword = Guid.NewGuid().ToString();

            //--Changes to speed up tests that don't require a new user, sharing a static user
            //--Also limiting table creation to once per test run
            if (!tablesCreated)
            {
                using (UserStore<IdentityUser> store = new UserStore<IdentityUser>(loggerFactory))
                {
                    var taskCreateTables = store.CreateTablesIfNotExists();
                    taskCreateTables.Wait();
                }

                tablesCreated = true;
            }

            if (User == null &&
                !NoCreateUserTests.Any(t => t == TestContext.TestName))
            {
                CreateUser();
            }
            //--
        }
        #endregion

        private void WriteLineObject<t>(t obj) where t : class
        {
            TestContext.WriteLine(typeof(t).Name);
            string strLine = obj == null ? "Null" : Newtonsoft.Json.JsonConvert.SerializeObject(obj, Newtonsoft.Json.Formatting.Indented);
            TestContext.WriteLine("{0}", strLine);
        }

        private Claim GenAdminClaim()
        {
            return new Claim(Constants.AccountClaimTypes.AccountTestAdminClaim, Guid.NewGuid().ToString());
        }

        private Claim GenAdminClaimEmptyValue()
        {
            return new Claim(Constants.AccountClaimTypes.AccountTestAdminClaim, string.Empty);
        }

        private Claim GenUserClaim()
        {
            return new Claim(Constants.AccountClaimTypes.AccountTestUserClaim, Guid.NewGuid().ToString());
        }
        private UserLoginInfo GenGoogleLogin()
        {
            return new UserLoginInfo(Constants.LoginProviders.GoogleProvider.LoginProvider,
                         Constants.LoginProviders.GoogleProvider.ProviderKey,
                         null);
        }

        private IdentityUser GenTestUser()
        {
            Guid id = Guid.NewGuid();
            IdentityUser user = new IdentityUser()
            {
                Email = id.ToString() + "@live.com",
                UserName = id.ToString("N"),
                LockoutEnabled = false,
                LockoutEndDateUtc = null,
                PhoneNumber = "555-555-5555",
                TwoFactorEnabled = false,
            };

            return user;
        }

        [TestMethod]
        [TestCategory("Identity.Dynamo.UserStore")]
        public void UserStoreCtors()
        {
            try
            {
                new UserStore<IdentityUser>(loggerFactory);
            }
            catch (ArgumentException) { }
        }

        [TestMethod]
        [TestCategory("Identity.Dynamo.UserStore")]
        public void CreateUser()
        {
            User = CreateTestUser();
            WriteLineObject<IdentityUser>(User);
        }

        private IdentityUser CreateTestUser(bool createPassword = true, bool createEmail = true
            , string emailAddress = null)
        {
            using (UserStore<IdentityUser> store = new UserStore<IdentityUser>(loggerFactory, new IdentityCloudContext<IdentityUser>()))
            {
                using (UserManager<IdentityUser> manager = new UserManager<IdentityUser>(store, null, new PasswordHasher<IdentityUser>(), null, null, lookupNormalizer, new IdentityErrorDescriber(), null, loggerFactory.CreateLogger<UserManager<IdentityUser>>()))
                {
                    var user = GenTestUser();
                    if (!createEmail)
                    {
                        user.Email = null;
                    }
                    else
                    {
                        if (string.IsNullOrWhiteSpace(emailAddress))
                        {
                            emailAddress = "user@example.com";
                        }
                        user.Email = emailAddress;
                    }
                    var taskUser = createPassword ?
                        manager.CreateAsync(user, DefaultUserPassword) :
                        manager.CreateAsync(user);
                    taskUser.Wait();
                    Assert.IsTrue(taskUser.Result.Succeeded, string.Concat(taskUser.Result.Errors));

                    for (int i = 0; i < 5; i++)
                    {
                        AddUserClaimHelper(user, GenAdminClaim());
                        AddUserLoginHelper(user, GenGoogleLogin());
                        AddUserRoleHelper(user, string.Format("{0}_{1}", Constants.AccountRoles.AccountTestUserRole, Guid.NewGuid().ToString("N")));
                    }

                    try
                    {
                        var task = store.CreateAsync(null, CancellationToken.None);
                        task.Wait();
                    }
                    catch (AggregateException agg)
                    {
                        agg.ValidateAggregateException<ArgumentException>();
                    }

                    var getUserTask = manager.FindByIdAsync(user.Id);
                    getUserTask.Wait();
                    return getUserTask.Result;
                }
            }
        }

        [TestMethod]
        [TestCategory("Identity.Dynamo.UserStore")]
        public async void DeleteUser()
        {
            using (UserStore<IdentityUser> store = new UserStore<IdentityUser>(loggerFactory, new IdentityCloudContext<IdentityUser>()))
            {
                using (UserManager<IdentityUser> manager = new UserManager<IdentityUser>(store, null, new PasswordHasher<IdentityUser>(), null, null, lookupNormalizer, new IdentityErrorDescriber(), null, loggerFactory.CreateLogger<UserManager<IdentityUser>>()))
                {
                    var user = GenTestUser();

                    var createResult = await manager.CreateAsync(user, DefaultUserPassword);
                    Assert.IsTrue(createResult.Succeeded, string.Concat(createResult.Errors));

                    for (int i = 0; i < 10; i++)
                    {
                        AddUserClaimHelper(user, GenAdminClaim());
                        AddUserLoginHelper(user, GenGoogleLogin());
                        AddUserRoleHelper(user, string.Format("{0}_{1}", Constants.AccountRoles.AccountTestUserRole, Guid.NewGuid().ToString("N")));
                    }

                    var foundUser = await manager.FindByIdAsync(user.Id);
                    WriteLineObject<IdentityUser>(foundUser);


                    DateTime start = DateTime.UtcNow;
                    var deleteResult = await manager.DeleteAsync(foundUser);
                    Assert.IsTrue(deleteResult.Succeeded, string.Concat(deleteResult.Errors));
                    TestContext.WriteLine("DeleteAsync: {0} seconds", (DateTime.UtcNow - start).TotalSeconds);

                    Thread.Sleep(1000);

                    var notFoundUser = await manager.FindByIdAsync(user.Id);
                    Assert.IsNull(notFoundUser, "Found user Id, user not deleted.");

                    var batchGet = store.Context.CreateBatchGet<IdentityUserIndex>(
                        new Amazon.DynamoDBv2.DataModel.DynamoDBOperationConfig()
                        {
                            TableNamePrefix = store.Context.TablePrefix
                        });
                    batchGet.ConsistentRead = true;
                    user.Logins.ToList().ForEach(l => batchGet.AddKey(l.Id));
                    await batchGet.ExecuteAsync();
                    Assert.IsFalse(batchGet.Results.Any(), "Login index records not deleted.");

                    try
                    {
                        await store.DeleteAsync(null, CancellationToken.None);
                    }
                    catch (ArgumentException)
                    {
                    }
                }
            }
        }

        [TestMethod]
        [TestCategory("Identity.Dynamo.UserStore")]
        public async void UpdateUser()
        {
            using (UserStore<IdentityUser> store = new UserStore<IdentityUser>(loggerFactory, new IdentityCloudContext<IdentityUser>()))
            {
                using (UserManager<IdentityUser> manager = new UserManager<IdentityUser>(store, null, new PasswordHasher<IdentityUser>(), null, null, lookupNormalizer, new IdentityErrorDescriber(), null, loggerFactory.CreateLogger<UserManager<IdentityUser>>()))
                {
                    var user = GenTestUser();
                    WriteLineObject<IdentityUser>(user);
                    var createResult = await manager.CreateAsync(user, DefaultUserPassword);
                    Assert.IsTrue(createResult.Succeeded, string.Concat(createResult.Errors));

                    var updateResult = await manager.UpdateAsync(user);
                    Assert.IsTrue(updateResult.Succeeded, string.Concat(updateResult.Errors));

                    try
                    {
                        await store.UpdateAsync(null, CancellationToken.None);
                    }
                    catch (ArgumentException) { }
                }
            }
        }

        [TestMethod]
        [TestCategory("Identity.Dynamo.UserStore")]
        public async void ChangeUserName()
        {
            using (UserStore<IdentityUser> store = new UserStore<IdentityUser>(loggerFactory, new IdentityCloudContext<IdentityUser>()))
            {
                using (UserManager<IdentityUser> manager = new UserManager<IdentityUser>(store, null, new PasswordHasher<IdentityUser>(), null, null, lookupNormalizer, new IdentityErrorDescriber(), null, loggerFactory.CreateLogger<UserManager<IdentityUser>>()))
                {
                    var firstUser = CreateTestUser();
                    TestContext.WriteLine("{0}", "Original User");
                    WriteLineObject<IdentityUser>(firstUser);
                    string originalPlainUserName = firstUser.UserName;
                    string originalUserId = firstUser.Id;
                    string userNameChange = Guid.NewGuid().ToString("N");
                    firstUser.UserName = userNameChange;

                    DateTime start = DateTime.UtcNow;
                    await manager.UpdateAsync(firstUser);
                    TestContext.WriteLine("UpdateAsync(ChangeUserName): {0} seconds", (DateTime.UtcNow - start).TotalSeconds);

                    var changedUser = await manager.FindByNameAsync(userNameChange);

                    TestContext.WriteLine("{0}", "Changed User");
                    WriteLineObject<IdentityUser>(changedUser);

                    Assert.IsNotNull(changedUser, "User not found by new username.");
                    Assert.IsFalse(originalPlainUserName.Equals(changedUser.UserName, StringComparison.OrdinalIgnoreCase), "UserName property not updated.");

                    Assert.AreEqual<int>(firstUser.Roles.Count, changedUser.Roles.Count, "Roles count are not equal");
                    Assert.IsTrue(changedUser.Roles.All(r => r.UserId == changedUser.Id.ToString()), "Roles partition keys are not equal to the new user id");

                    Assert.AreEqual<int>(firstUser.Claims.Count, changedUser.Claims.Count, "Claims count are not equal");
                    Assert.IsTrue(changedUser.Claims.All(r => r.UserId == changedUser.Id.ToString()), "Claims partition keys are not equal to the new user id");

                    Assert.AreEqual<int>(firstUser.Logins.Count, changedUser.Logins.Count, "Logins count are not equal");
                    Assert.IsTrue(changedUser.Logins.All(r => r.UserId == changedUser.Id.ToString()), "Logins partition keys are not equal to the new user id");

                    Assert.AreEqual<string>(originalUserId, changedUser.Id, "User Ids are not the same.");
                    Assert.AreNotEqual<string>(originalPlainUserName, changedUser.UserName, "UserNames are the same.");

                    //Check email
                    var foundEmail = await manager.FindByEmailAsync(changedUser.Email);

                    //Check logins
                    foreach (var log in foundEmail.Logins)
                    {
                        var foundLogin = await manager.FindByLoginAsync(log.LoginProvider, log.ProviderKey);
                        
                        Assert.IsNotNull(foundLogin, "User not found by login.");
                        Assert.AreNotEqual<string>(originalPlainUserName, foundLogin.UserName, "Login user id not changed");
                    }

                    try
                    {
                        await store.UpdateAsync(null, CancellationToken.None);
                    }
                    catch (ArgumentException) { }
                }
            }
        }

        [TestMethod]
        [TestCategory("Identity.Dynamo.UserStore")]
        public async void FindUserByEmail()
        {
            using (UserStore<IdentityUser> store = new UserStore<IdentityUser>(loggerFactory, new IdentityCloudContext<IdentityUser>()))
            {
                using (UserManager<IdentityUser> manager = new UserManager<IdentityUser>(store, null, new PasswordHasher<IdentityUser>(), null, null, lookupNormalizer, new IdentityErrorDescriber(), null, loggerFactory.CreateLogger<UserManager<IdentityUser>>()))
                {
                    var user = User;
                    WriteLineObject<IdentityUser>(user);

                    DateTime start = DateTime.UtcNow;
                    var foundUser = await manager.FindByEmailAsync(user.Email);
                    TestContext.WriteLine("FindByEmailAsync: {0} seconds", (DateTime.UtcNow - start).TotalSeconds);

                    Assert.AreEqual<string>(user.Email, foundUser.Email, "Found user email not equal");

                    CreateTestUser(true, true, user.Email);

                    start = DateTime.UtcNow;
                    foundUser = await manager.FindByEmailAsync(user.Email);
                    TestContext.WriteLine("FindByEmailAsync: {0} seconds", (DateTime.UtcNow - start).TotalSeconds);
                    Assert.IsNotNull(foundUser, "User should be not null.");

                    //Negative cases
                    string bogusEmail = "234567@aldskjfalsdfj43344.com";
                    var foundUser2 = await manager.FindByEmailAsync(bogusEmail);
                    Assert.IsNull(foundUser2, "User should be null.");

                    try
                    {
                        await store.FindByEmailAsync(null, CancellationToken.None);
                    }
                    catch (ArgumentException) { }

                }
            }
        }

        [TestMethod]
        [TestCategory("Identity.Dynamo.UserStore")]
        public async void FindUsersByEmail()
        {
            string strEmail = Guid.NewGuid().ToString() + "@live.com";

            using (UserStore<IdentityUser> store = new UserStore<IdentityUser>(loggerFactory, new IdentityCloudContext<IdentityUser>()))
            {
                using (UserManager<IdentityUser> manager = new UserManager<IdentityUser>(store, null, new PasswordHasher<IdentityUser>(), null, null, lookupNormalizer, new IdentityErrorDescriber(), null, loggerFactory.CreateLogger<UserManager<IdentityUser>>()))
                {
                    List<IdentityUser> listCreated = new List<IdentityUser>();
                    for (int i = 0; i < 11; i++)
                    {
                        listCreated.Add(CreateTestUser(true, true, strEmail));
                    }

                    DateTime start = DateTime.UtcNow;
                    TestContext.WriteLine("FindAllByEmailAsync: {0}", strEmail);

                    var foundUsers = new List<IdentityUser>(
                        await store.FindAllByEmailAsync(strEmail, CancellationToken.None));
                    TestContext.WriteLine("FindAllByEmailAsync: {0} seconds", (DateTime.UtcNow - start).TotalSeconds);
                    TestContext.WriteLine("Users Found: {0}", foundUsers.Count());
                    Assert.AreEqual<int>(listCreated.Count, foundUsers.Count(), "Found users by email not equal");

                    //Change email and check results
                    string strEmailChanged = $"{Guid.NewGuid()}@live.com";
                    var userToChange = listCreated.Last();
                    await manager.SetEmailAsync(userToChange, strEmailChanged);

                    var changedUser = await manager.FindByEmailAsync(strEmailChanged);
                    Assert.AreEqual<string>(userToChange.Id, changedUser.Id, "Found user by email not equal");
                    Assert.AreNotEqual<string>(userToChange.Email, changedUser.Email, "Found user by email not changed");


                    //Make sure changed user doesn't show up in previous query
                    start = DateTime.UtcNow;

                    var foundUser = new List<IdentityUser>(
                        await store.FindAllByEmailAsync(strEmail, CancellationToken.None));
                    TestContext.WriteLine("FindAllByEmailAsync: {0} seconds", (DateTime.UtcNow - start).TotalSeconds);
                    TestContext.WriteLine("Users Found: {0}", foundUser.Count());
                    Assert.AreEqual<int>(listCreated.Count - 1, foundUser.Count(), "Found users by email not equal");

                    //negative tests
                    try
                    {
                        await store.FindAllByEmailAsync(string.Empty, CancellationToken.None);
                    }
                    catch (ArgumentException) { }

                }
            }
        }

        [TestMethod]
        [TestCategory("Identity.Dynamo.UserStore")]
        public async void FindUserById()
        {
            using (UserStore<IdentityUser> store = new UserStore<IdentityUser>(loggerFactory, new IdentityCloudContext<IdentityUser>()))
            {
                using (UserManager<IdentityUser> manager = new UserManager<IdentityUser>(store, null, new PasswordHasher<IdentityUser>(), null, null, lookupNormalizer, new IdentityErrorDescriber(), null, loggerFactory.CreateLogger<UserManager<IdentityUser>>()))
                {
                    var user = User;
                    DateTime start = DateTime.UtcNow;
                    var foundUser = await manager.FindByIdAsync(user.Id);
                    TestContext.WriteLine("FindByIdAsync: {0} seconds", (DateTime.UtcNow - start).TotalSeconds);

                    Assert.AreEqual<string>(user.Id, foundUser.Id, "Found user Id not equal");

                    try
                    {
                        await store.FindByIdAsync(null, CancellationToken.None);
                    }
                    catch (ArgumentNullException) { }
                    try
                    {
                        await store.FindByIdAsync(string.Empty, CancellationToken.None);
                    }
                    catch (ArgumentException) { }
                }
            }
        }

        [TestMethod]
        [TestCategory("Identity.Dynamo.UserStore")]
        public async void FindUserByName()
        {
            using (UserStore<IdentityUser> store = new UserStore<IdentityUser>(loggerFactory, new IdentityCloudContext<IdentityUser>()))
            {
                using (UserManager<IdentityUser> manager = new UserManager<IdentityUser>(store, null, new PasswordHasher<IdentityUser>(), null, null, lookupNormalizer, new IdentityErrorDescriber(), null, loggerFactory.CreateLogger<UserManager<IdentityUser>>()))
                {
                    var user = User;
                    WriteLineObject<IdentityUser>(user);
                    DateTime start = DateTime.UtcNow;
                    var foundUser = await manager.FindByNameAsync(user.UserName);
                    TestContext.WriteLine("FindByNameAsync: {0} seconds", (DateTime.UtcNow - start).TotalSeconds);

                    Assert.AreEqual<string>(user.UserName, foundUser.UserName, "Found user UserName not equal");
                }
            }
        }

        [TestMethod]
        [TestCategory("Identity.Dynamo.UserStore")]
        public void AddUserLogin()
        {
            var user = CreateTestUser(false);
            WriteLineObject<IdentityUser>(user);
            AddUserLoginHelper(user, GenGoogleLogin());
        }

        public void AddUserLoginHelper(IdentityUser user, UserLoginInfo loginInfo)
        {
            using (UserStore<IdentityUser> store = new UserStore<IdentityUser>(loggerFactory, new IdentityCloudContext<IdentityUser>()))
            {
                using (UserManager<IdentityUser> manager = new UserManager<IdentityUser>(store, null, new PasswordHasher<IdentityUser>(), null, null, lookupNormalizer, new IdentityErrorDescriber(), null, loggerFactory.CreateLogger<UserManager<IdentityUser>>()))
                {
                    var userAddLoginTask = manager.AddLoginAsync(user, loginInfo);
                    userAddLoginTask.Wait();
                    Assert.IsTrue(userAddLoginTask.Result.Succeeded, string.Concat(userAddLoginTask.Result.Errors));

                    var loginGetTask = manager.GetLoginsAsync(user);
                    loginGetTask.Wait();
                    Assert.IsTrue(loginGetTask.Result
                        .Any(log => log.LoginProvider == loginInfo.LoginProvider
                            & log.ProviderKey == loginInfo.ProviderKey), "LoginInfo not found: GetLoginsAsync");

                    var userLoginInfo = loginGetTask.Result.First();
                    var loginGetTask2 = manager.FindByLoginAsync(userLoginInfo.LoginProvider, userLoginInfo.ProviderKey);
                    loginGetTask2.Wait();
                    Assert.IsNotNull(loginGetTask2.Result, "LoginInfo not found: FindAsync");

                }
            }
        }


        [TestMethod]
        [TestCategory("Identity.Dynamo.UserStore")]
        public async void AddRemoveUserLogin()
        {
            using (UserStore<IdentityUser> store = new UserStore<IdentityUser>(loggerFactory, new IdentityCloudContext<IdentityUser>()))
            {
                using (UserManager<IdentityUser> manager = new UserManager<IdentityUser>(store, null, new PasswordHasher<IdentityUser>(), null, null, lookupNormalizer, new IdentityErrorDescriber(), null, loggerFactory.CreateLogger<UserManager<IdentityUser>>()))
                {
                    var user = GenTestUser();
                    WriteLineObject<IdentityUser>(user);
                    var createResult = await manager.CreateAsync(user, DefaultUserPassword);
                    Assert.IsTrue(createResult.Succeeded, string.Concat(createResult.Errors));
                    
                    var loginInfo = GenGoogleLogin();
                    var addedLogin = await manager.AddLoginAsync(user, loginInfo);
                    Assert.IsTrue(addedLogin.Succeeded, string.Concat(addedLogin.Errors));

                    var foundLogins = await manager.GetLoginsAsync(user);
                    Assert.IsTrue(foundLogins
                        .Any(log => log.LoginProvider == loginInfo.LoginProvider
                            & log.ProviderKey == loginInfo.ProviderKey), "LoginInfo not found: GetLoginsAsync");

                    var userLoginInfo = foundLogins.First();
                    var foundLogins2 = await manager.FindByLoginAsync(userLoginInfo.LoginProvider, userLoginInfo.ProviderKey);
                    Assert.IsNotNull(foundLogins2, "LoginInfo not found: FindAsync");

                    var notFoundLogins = await manager.FindByLoginAsync(Guid.NewGuid().ToString("N"), Guid.NewGuid().ToString("N"));
                    Assert.IsNull(notFoundLogins, "LoginInfo found: FindAsync");


                    await manager.RemoveLoginAsync(user, string.Empty, loginInfo.ProviderKey);

                    await manager.RemoveLoginAsync(user, loginInfo.LoginProvider, string.Empty);

                    var removedLogin = await manager.RemoveLoginAsync(user, loginInfo.LoginProvider, loginInfo.ProviderKey);
                    Assert.IsTrue(removedLogin.Succeeded, string.Concat(removedLogin.Errors));
                    var foundLogins3 = await manager.GetLoginsAsync(user);
                    Assert.IsTrue(!foundLogins3.Any(), "LoginInfo not removed");

                    //Negative cases

                    var notFoundLogin = await manager.FindByLoginAsync("asdfasdf", "http://4343443dfaksjfaf");
                    Assert.IsNull(notFoundLogin, "LoginInfo found: FindAsync");

                    try
                    {
                        await store.AddLoginAsync(null, loginInfo, CancellationToken.None);
                    }
                    catch (ArgumentException) { }

                    try
                    {
                        await store.AddLoginAsync(user, null, CancellationToken.None);
                    }
                    catch (ArgumentException) { }

                    try
                    {
                        await store.RemoveLoginAsync(null, loginInfo, CancellationToken.None);
                    }
                    catch (ArgumentException) { }

                    try
                    {
                        await store.RemoveLoginAsync(user, null, CancellationToken.None);
                    }
                    catch (ArgumentException) { }

                    try
                    {
                        await store.FindByLoginAsync(null, null, CancellationToken.None);
                    }
                    catch (ArgumentNullException) { }

                    try
                    {
                        await store.GetLoginsAsync(null, CancellationToken.None);
                    }
                    catch (ArgumentException) { }
                }
            }
        }

        [TestMethod]
        [TestCategory("Identity.Dynamo.UserStore")]
        public void AddUserRole()
        {
            string strUserRole = string.Format("{0}_{1}", Constants.AccountRoles.AccountTestUserRole, Guid.NewGuid().ToString("N"));
            WriteLineObject<IdentityUser>(User);
            AddUserRoleHelper(User, strUserRole);
        }

        public void AddUserRoleHelper(IdentityUser user, string roleName)
        {
            using (RoleStore<IdentityRole> rstore = new RoleStore<IdentityRole>(loggerFactory))
            {
                var userRole = rstore.FindByNameAsync(roleName, CancellationToken.None);
                userRole.Wait();

                if (userRole.Result == null)
                {
                    var taskUser = rstore.CreateAsync(new IdentityRole(roleName), CancellationToken.None);
                    taskUser.Wait();
                }
            }

            using (UserStore<IdentityUser> store = new UserStore<IdentityUser>(loggerFactory, new IdentityCloudContext<IdentityUser>()))
            {
                using (UserManager<IdentityUser> manager = new UserManager<IdentityUser>(store, null, new PasswordHasher<IdentityUser>(), null, null, lookupNormalizer, new IdentityErrorDescriber(), null, loggerFactory.CreateLogger<UserManager<IdentityUser>>()))
                {
                    var userRoleTask = manager.AddToRoleAsync(user, roleName);
                    userRoleTask.Wait();
                    Assert.IsTrue(userRoleTask.Result.Succeeded, string.Concat(userRoleTask.Result.Errors));

                    var roles2Task = manager.IsInRoleAsync(user, roleName);
                    roles2Task.Wait();
                    Assert.IsTrue(roles2Task.Result, "Role not found");

                }
            }
        }

        [TestMethod]
        [TestCategory("Identity.Dynamo.UserStore")]
        public async void AddRemoveUserRole()
        {
            string roleName = string.Format("{0}_{1}", Constants.AccountRoles.AccountTestAdminRole, Guid.NewGuid().ToString("N"));

            using (RoleStore<IdentityRole> rstore = new RoleStore<IdentityRole>(loggerFactory))
            {
                await rstore.CreateAsync(new IdentityRole(roleName), CancellationToken.None);

                await rstore.FindByNameAsync(roleName, CancellationToken.None);
            }

            using (UserStore<IdentityUser> store = new UserStore<IdentityUser>(loggerFactory, new IdentityCloudContext<IdentityUser>()))
            {
                using (UserManager<IdentityUser> manager = new UserManager<IdentityUser>(store, null, new PasswordHasher<IdentityUser>(), null, null, lookupNormalizer, new IdentityErrorDescriber(), null, loggerFactory.CreateLogger<UserManager<IdentityUser>>()))
                {
                    var user = User;
                    WriteLineObject<IdentityUser>(user);
                    var userRole = await manager.AddToRoleAsync(user, roleName);
                    Assert.IsTrue(userRole.Succeeded, string.Concat(userRole.Errors));

                    var roles = await manager.GetRolesAsync(user);
                    Assert.IsTrue(roles.Contains(roleName), "Role not found");

                    var roles2 = await manager.IsInRoleAsync(user, roleName);
                    Assert.IsTrue(roles2, "Role not found");

                    var userRemove = await manager.RemoveFromRoleAsync(user, roleName);
                    var roles3 = await manager.GetRolesAsync(user);
                    Assert.IsFalse(roles3.Contains(roleName), "Role not removed.");

                    try
                    {
                        await store.AddToRoleAsync(null, roleName, CancellationToken.None);
                    }
                    catch (ArgumentException) { }

                    try
                    {
                        await store.AddToRoleAsync(user, null, CancellationToken.None);
                    }
                    catch (ArgumentException) { }

                    try
                    {
                        await store.AddToRoleAsync(user, Guid.NewGuid().ToString(), CancellationToken.None);
                    }
                    catch (ArgumentException) { }

                    try
                    {
                        await store.RemoveFromRoleAsync(null, roleName, CancellationToken.None);
                    }
                    catch (ArgumentException) { }

                    try
                    {
                        await store.RemoveFromRoleAsync(user, null, CancellationToken.None);
                    }
                    catch (ArgumentException) { }

                    try
                    {
                        store.GetRolesAsync(null, CancellationToken.None).Wait();
                    }
                    catch (ArgumentException) { }

                }
            }
        }

        [TestMethod]
        [TestCategory("Identity.Dynamo.UserStore")]
        public async void IsUserInRole()
        {
            using (UserStore<IdentityUser> store = new UserStore<IdentityUser>(loggerFactory, new IdentityCloudContext<IdentityUser>()))
            {
                using (UserManager<IdentityUser> manager = new UserManager<IdentityUser>(store, null, new PasswordHasher<IdentityUser>(), null, null, lookupNormalizer, new IdentityErrorDescriber(), null, loggerFactory.CreateLogger<UserManager<IdentityUser>>()))
                {
                    var user = User;
                    WriteLineObject<IdentityUser>(user);
                    string roleName = string.Format("{0}_{1}", Constants.AccountRoles.AccountTestUserRole, Guid.NewGuid().ToString("N"));

                    AddUserRoleHelper(user, roleName);

                    var roles2 = await manager.IsInRoleAsync(user, roleName);
                    Assert.IsTrue(roles2, "Role not found");


                    var roles3 = await store.IsInRoleAsync(user, Guid.NewGuid().ToString(), CancellationToken.None);
                    Assert.IsFalse(roles3, "Role should not be found");

                    try
                    {
                        await store.IsInRoleAsync(null, roleName, CancellationToken.None);
                    }
                    catch (ArgumentException) { }

                    try
                    {
                        await store.IsInRoleAsync(user, null, CancellationToken.None);
                    }
                    catch (ArgumentException) { }
                }
            }
        }

        [TestMethod]
        [TestCategory("Identity.Dynamo.UserStore")]
        public void AddUserClaim()
        {
            WriteLineObject<IdentityUser>(User);
            AddUserClaimHelper(User, GenUserClaim());
        }

        private void AddUserClaimHelper(IdentityUser user, Claim claim)
        {
            using (UserStore<IdentityUser> store = new UserStore<IdentityUser>(loggerFactory, new IdentityCloudContext<IdentityUser>()))
            {
                using (UserManager<IdentityUser> manager = new UserManager<IdentityUser>(store, null, new PasswordHasher<IdentityUser>(), null, null, lookupNormalizer, new IdentityErrorDescriber(), null, loggerFactory.CreateLogger<UserManager<IdentityUser>>()))
                {
                    var userClaimTask = manager.AddClaimAsync(user, claim);
                    userClaimTask.Wait();
                    Assert.IsTrue(userClaimTask.Result.Succeeded, string.Concat(userClaimTask.Result.Errors));
                    var claimsTask = manager.GetClaimsAsync(user);
                    claimsTask.Wait();
                    Assert.IsTrue(claimsTask.Result.Any(c => c.Value == claim.Value & c.ValueType == claim.ValueType), "Claim not found");
                }
            }

        }

        [TestMethod]
        [TestCategory("Identity.Dynamo.UserStore")]
        public async void AddRemoveUserClaim()
        {
            using (UserStore<IdentityUser> store = new UserStore<IdentityUser>(loggerFactory, new IdentityCloudContext<IdentityUser>()))
            {
                using (UserManager<IdentityUser> manager = new UserManager<IdentityUser>(store, null, new PasswordHasher<IdentityUser>(), null, null, lookupNormalizer, new IdentityErrorDescriber(), null, loggerFactory.CreateLogger<UserManager<IdentityUser>>()))
                {
                    var user = User;
                    WriteLineObject<IdentityUser>(user);
                    Claim claim = GenAdminClaim();
                    var userClaim = await manager.AddClaimAsync(user, claim);
                    Assert.IsTrue(userClaim.Succeeded, string.Concat(userClaim.Errors));
                    var claims = await manager.GetClaimsAsync(user);
                    Assert.IsTrue(claims.Any(c => c.Value == claim.Value & c.ValueType == claim.ValueType), "Claim not found");


                    var userRemoveClaim = await manager.RemoveClaimAsync(user, claim);
                    Assert.IsTrue(userClaim.Succeeded, string.Concat(userClaim.Errors));
                    var claims2 = await manager.GetClaimsAsync(user);
                    Assert.IsTrue(!claims2.Any(c => c.Value == claim.Value & c.ValueType == claim.ValueType), "Claim not removed");

                    //adding test for removing an empty claim
                    Claim claimEmpty = GenAdminClaimEmptyValue();
                    var userClaim2 = await manager.AddClaimAsync(user, claimEmpty);
                    Assert.IsTrue(userClaim2.Succeeded, string.Concat(userClaim2.Errors));

                    var userRemoveClaim2 = await manager.RemoveClaimAsync(user, claimEmpty);
                    Assert.IsTrue(userRemoveClaim2.Succeeded, string.Concat(userRemoveClaim2.Errors));

                    try
                    {
                        await store.AddClaimAsync(null, claim, CancellationToken.None);
                    }
                    catch (ArgumentException) { }

                    try
                    {
                        await store.AddClaimAsync(user, null, CancellationToken.None);
                    }
                    catch (ArgumentException) { }

                    try
                    {
                        await store.RemoveClaimAsync(null, claim, CancellationToken.None);
                    }
                    catch (ArgumentException) { }

                    try
                    {
                        await store.RemoveClaimAsync(user, null, CancellationToken.None);
                    }
                    catch (ArgumentException) { }

                    try
                    {
                        await
                            store.RemoveClaimAsync(user, new Claim(string.Empty, Guid.NewGuid().ToString()),
                                CancellationToken.None);
                    }
                    catch (ArgumentException) { }

                    try
                    {
                        await store.RemoveClaimAsync(user, new Claim(claim.Type, null), CancellationToken.None);
                    }
                    catch (ArgumentException) { }

                    try
                    {
                        await store.GetClaimsAsync(null, CancellationToken.None);
                    }
                    catch (ArgumentException) { }
                }
            }
        }

        [TestMethod]
        [TestCategory("Identity.Dynamo.UserStore")]
        public async void ThrowIfDisposed()
        {
            UserStore<IdentityUser> store = new UserStore<IdentityUser>(loggerFactory);
            store.Dispose();
            GC.Collect();
            try
            {
                await store.DeleteAsync(null, CancellationToken.None);
            }
            catch (ArgumentException agg)
            {
            }
        }

    }
}
