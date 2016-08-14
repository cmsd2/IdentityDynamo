// MIT License Copyright 2014 (c) David Melendez. All rights reserved. See License.txt in the project root for license information.
using ElCamino.AspNet.Identity.Dynamo.Model;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Linq.Expressions;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using ElCamino.AspNet.Identity.Dynamo.Helpers;
using Amazon.DynamoDBv2.DocumentModel;
using Amazon.DynamoDBv2.DataModel;
using Amazon.DynamoDBv2.Model;
using Amazon.DynamoDBv2;
using System.Threading;
using System.Collections.Concurrent;
using System.Net.Mail;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;

namespace ElCamino.AspNet.Identity.Dynamo
{
    public class UserStore<TUser> : UserStore<TUser, IdentityRole, IdentityUserLogin, IdentityUserRole, IdentityUserClaim>, IUserStore<TUser> where TUser : IdentityUser, new()
    {
        public UserStore(ILoggerFactory loggerFactory)
            : this(loggerFactory, new IdentityCloudContext<TUser>())
        {
           
        }

        public UserStore(ILoggerFactory loggerFactory, IdentityCloudContext<TUser> context)
            : base(loggerFactory, context)
        {
        }

        //Fixing code analysis issue CA1063
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
        }
    }

    public class UserStore<TUser, TRole, TUserLogin, TUserRole, TUserClaim> : IUserLoginStore<TUser>
        , IUserClaimStore<TUser>
        , IUserRoleStore<TUser>, IUserPasswordStore<TUser>
        , IUserSecurityStampStore<TUser>, IQueryableUserStore<TUser>
        , IUserEmailStore<TUser>, IUserPhoneNumberStore<TUser>
        , IUserTwoFactorStore<TUser>
        , IUserLockoutStore<TUser>
        , IUserStore<TUser>
        , IDisposable
        where TUser : IdentityUser<string, TUserLogin, TUserRole, TUserClaim>, new()
        where TRole : IdentityRole<string, TUserRole>, new()
        where TUserLogin : IdentityUserLogin, new()
        where TUserRole : IdentityUserRole, new()
        where TUserClaim : IdentityUserClaim, new()
    {
        private bool _disposed;
        private IQueryable<TUser> _users;
        private ILogger logger;


        public UserStore(ILoggerFactory loggerFactory, IdentityCloudContext<TUser, TRole, string, TUserLogin, TUserRole, TUserClaim> context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }
            logger = loggerFactory.CreateLogger("UserStore");
            Context = context;
        }

        public async Task CreateTablesIfNotExists()
        {
            await Task.WhenAll(new Task[]
            { 
                Context.CreateUserTableAsync(),
                Context.CreateIndexTableAsync(),
                Context.CreateRoleTableAsync(),
                Context.CreateUserRoleTableAsync(),
                Context.CreateUserLoginTableAsync()
        });
        }

        public async Task AddClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (claims == null)
            {
                throw new ArgumentNullException(nameof(claims));
            }

            await Task.WhenAll(claims.Select(claim => AddClaimAsync(user, claim, cancellationToken)));
        }

        public virtual async Task AddClaimAsync(TUser user, Claim claim, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }


            TUserClaim item = Activator.CreateInstance<TUserClaim>();
            item.UserId = user.UserId;
            item.ClaimType = claim.Type;
            item.ClaimValue = claim.Value;
            item.UserName = user.UserName;
            item.Email = user.Email;
            ((IGenerateKeys)item).GenerateKeys();


            user.Claims.Add(item);

            var putRequest = new PutItemRequest()
            {
                TableName = Context.FormatTableNameWithPrefix(Constants.TableNames.UsersTable),
                Item = Context.ToDocument<TUserClaim>(item).ToAttributeMap(),
            };


            await Context.Client.PutItemAsync(putRequest, cancellationToken);
                    
        }

        public virtual async Task AddLoginAsync(TUser user, UserLoginInfo login, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (login == null)
            {
                throw new ArgumentNullException(nameof(login));
            }

            TUserLogin item = Activator.CreateInstance<TUserLogin>();
            item.UserId = user.Id;
            item.ProviderKey = login.ProviderKey;
            item.LoginProvider = login.LoginProvider;
            item.Email = user.Email;
            item.UserName = user.UserName;
            ((IGenerateKeys)item).GenerateKeys();

            user.Logins.Add(item);
            IdentityUserIndex index = new IdentityUserIndex();
            index.Id = item.Id;
            index.UserId = item.UserId;

            BatchWriteItemRequest batchWriteReq = new BatchWriteItemRequest();
            batchWriteReq.RequestItems = new Dictionary<string, List<WriteRequest>>(10);
            List<WriteRequest> listUserwr = new List<WriteRequest>(10);
            List<WriteRequest> listIndexwr = new List<WriteRequest>(10);

            var indexwr = new WriteRequest();
            indexwr.PutRequest = new PutRequest();
            indexwr.PutRequest.Item = Context.ToDocument<IdentityUserIndex>(index).ToAttributeMap();
            listIndexwr.Add(indexwr);

            var userwr = new WriteRequest();
            userwr.PutRequest = new PutRequest();
            userwr.PutRequest.Item = Context.ToDocument<TUserLogin>(item).ToAttributeMap();
            listUserwr.Add(userwr);

            batchWriteReq.RequestItems.Add(Context.FormatTableNameWithPrefix(Constants.TableNames.UserLoginsTable), listUserwr);
            batchWriteReq.RequestItems.Add(Context.FormatTableNameWithPrefix(Constants.TableNames.IndexTable), listIndexwr);

            await Context.Client.BatchWriteItemAsync(batchWriteReq, cancellationToken);
        }

        public virtual async Task AddToRoleAsync(TUser user, string roleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (string.IsNullOrWhiteSpace(roleName))
            {
                throw new ArgumentException(IdentityResources.ValueCannotBeNullOrEmpty, nameof(roleName));
            }

            TRole roleT = Activator.CreateInstance<TRole>();
            roleT.Name = roleName;
            ((IGenerateKeys)roleT).GenerateKeys();

            TUserRole userToRole = Activator.CreateInstance<TUserRole>();
            userToRole.UserId = user.Id;
            userToRole.RoleId = roleT.Id;
            userToRole.RoleName = roleT.Name;
            userToRole.Email = user.Email;
            userToRole.UserName = user.UserName;
            TUserRole item = userToRole;

            ((IGenerateKeys)item).GenerateKeys();

            user.Roles.Add(item);
            roleT.Users.Add(item);

            await Context.SaveAsync<TUserRole>(userToRole, new DynamoDBOperationConfig()
            {
                TableNamePrefix = this.Context.TablePrefix,
                ConsistentRead = true,
            }, cancellationToken);

        }

        public virtual async Task<IdentityResult> CreateAsync(TUser user, CancellationToken cancellationToken)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            ((IGenerateKeys)user).GenerateKeys();

            try
            {
                await Context.SaveAsync<TUser>(user, new DynamoDBOperationConfig()
                {
                    TableNamePrefix = this.Context.TablePrefix,
                    ConsistentRead = true
                });
            }
            catch (Exception)
            {
                return IdentityResult.Failed(new IdentityErrorDescriber().DefaultError());
            }
        
            return IdentityResult.Success;
        }

        public virtual async Task<IdentityResult> DeleteAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            try
            {
                BatchOperationHelper batchHelper = new BatchOperationHelper();
                batchHelper.Add(Context.FormatTableNameWithPrefix(Constants.TableNames.UsersTable), CreateDeleteRequestForUser(user.UserId, user.Id));
                user.Claims.ToList().ForEach(c => { batchHelper.Add(Context.FormatTableNameWithPrefix(Constants.TableNames.UsersTable), CreateDeleteRequestForUser(c.UserId, c.Id)); });
                user.Roles.ToList().ForEach(r => { batchHelper.Add(Context.FormatTableNameWithPrefix(Constants.TableNames.UsersTable), CreateDeleteRequestForUser(r.UserId, r.Id)); });
                user.Logins.ToList().ForEach(l =>
                {
                    batchHelper.Add(Context.FormatTableNameWithPrefix(Constants.TableNames.UsersTable), CreateDeleteRequestForUser(l.UserId, l.Id));
                    batchHelper.Add(Context.FormatTableNameWithPrefix(Constants.TableNames.IndexTable), CreateDeleteRequestForIndex(l.Id));
                });

                await batchHelper.ExecuteBatchAsync(Context.Client);
            }
            catch (Exception e)
            {
                logger.LogInformation($"error deleting user: {e}");
                return IdentityResult.Failed(new IdentityErrorDescriber().DefaultError());
            }
            
            return IdentityResult.Success;
        }

        private WriteRequest CreateDeleteRequestForUser(string UserId, string Id)
        {
            var wr = new WriteRequest();
            wr.DeleteRequest = new DeleteRequest();
            wr.DeleteRequest.Key = new Dictionary<string, AttributeValue>(2);
            wr.DeleteRequest.Key.Add("UserId", new AttributeValue() { S = UserId.ToString() });
            wr.DeleteRequest.Key.Add("Id", new AttributeValue() { S = Id.ToString() });
            return wr;
        }

        private WriteRequest CreateDeleteRequestForUserClaim(string userId, string claimId)
        {
            var wr = new WriteRequest();
            wr.DeleteRequest = new DeleteRequest();
            wr.DeleteRequest.Key = new Dictionary<string, AttributeValue>(2);
            wr.DeleteRequest.Key.Add("UserId", new AttributeValue() { S = userId.ToString() });
            wr.DeleteRequest.Key.Add("Id", new AttributeValue() { S = claimId.ToString() });
            return wr;
        }

        private WriteRequest CreateDeleteRequestForIndex(string id)
        {
            var iwr = new WriteRequest();
            iwr.DeleteRequest = new DeleteRequest();
            iwr.DeleteRequest.Key = new Dictionary<string, AttributeValue>(1);
            iwr.DeleteRequest.Key.Add("Id", new AttributeValue() { S = id.ToString() });
            return iwr;
        }

        public void Dispose()
        {
            this.Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed && disposing)
            {
                if (this.Context != null)
                {
                    this.Context.Dispose();
                }
                _disposed = true;
                Context = null;
            }
        }

        public virtual async Task<TUser> FindAsync(UserLoginInfo login, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (login == null)
            {
                throw new ArgumentNullException(nameof(login));
            }

            return await Context.LoadAsync<IdentityUserIndex<string>>(login.GenerateRowKeyUserLoginInfo(),
                new DynamoDBOperationConfig()
                {
                    TableNamePrefix = Context.TablePrefix,
                    ConsistentRead = true,
                }, cancellationToken)
                .ContinueWith<Task<TUser>>(new Func<Task<IdentityUserIndex<string>>, Task<TUser>>((index) =>
                {
                    if (index.Result != null)
                    {
                        return FindByIdAsync(index.Result.UserId, cancellationToken);
                    }
                    return new TaskFactory<TUser>().StartNew(() => null, cancellationToken);

                }), cancellationToken).Unwrap();

        }

        public async Task<TUser> FindByEmailAsync(string email, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (string.IsNullOrWhiteSpace(email))
            {
                throw new ArgumentException(IdentityResources.ValueCannotBeNullOrEmpty, nameof(email));
            }

            return await Context.Client.QueryAsync(new QueryRequest()
            {
                TableName = Context.FormatTableNameWithPrefix(Constants.TableNames.UsersTable),
                IndexName = Constants.SecondaryIndexNames.UserEmailIndex,
                KeyConditions = new Dictionary<string, Condition>()
                    { 
                        {"NormalizedEmail", new Condition()
                            { 
                                ComparisonOperator = ComparisonOperator.EQ,
                                AttributeValueList = new List<AttributeValue>() { new AttributeValue() { S = email }}
                            }
                        }
                }
            }, cancellationToken)
            .ContinueWith<TUser>(new Func<Task<QueryResponse>, TUser>((qResponse) =>
            {
                return ConvertResponseToUser(qResponse.Result.Items);
            }), cancellationToken);
            

        }

        public async Task<IEnumerable<TUser>> FindAllByEmailAsync(string email, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (string.IsNullOrWhiteSpace(email))
            {
                throw new ArgumentException(IdentityResources.ValueCannotBeNullOrEmpty, nameof(email));
            }

            return await Context.Client.QueryAsync(new QueryRequest()
            {
                TableName = Context.FormatTableNameWithPrefix(Constants.TableNames.UsersTable),
                IndexName = Constants.SecondaryIndexNames.UserEmailIndex,
                KeyConditions = new Dictionary<string, Condition>()
                    { 
                        {"Email", new Condition()
                            { 
                                ComparisonOperator = ComparisonOperator.EQ,
                                AttributeValueList = new List<AttributeValue>() { new AttributeValue() { S = email }}
                            }
                        }
                }
            }, cancellationToken)
            .ContinueWith<IEnumerable<TUser>>(new Func<Task<QueryResponse>, IEnumerable<TUser>>((qResponse) =>
            {
                return ConvertResponseToUsers(qResponse.Result.Items);
            }), cancellationToken);


        }


        public virtual async Task<TUser> FindByIdAsync(string userId, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            if (userId == null)
            {
                throw new ArgumentNullException(nameof(userId));
            }
            if (string.IsNullOrWhiteSpace(userId.ToString()))
            {
                throw new ArgumentException(IdentityResources.ValueCannotBeNullOrEmpty, nameof(userId));
            }


            return await Context.Client.QueryAsync(new QueryRequest()
            {
                ConsistentRead = true,
                TableName = Context.FormatTableNameWithPrefix(Constants.TableNames.UsersTable),
                KeyConditions = new Dictionary<string, Condition>()
                { 
                    {"UserId", new Condition()
                        { 
                            ComparisonOperator = ComparisonOperator.EQ,
                            AttributeValueList = new List<AttributeValue>() { new AttributeValue() { S = userId.ToString() }}
                        }
                    }
                }
            }, cancellationToken)
            .ContinueWith<TUser>(new Func<Task<QueryResponse>, TUser>(
                (qResponse) => ConvertResponseToUser(qResponse.Result.Items)),
                cancellationToken);
           
        }

        private IEnumerable<TUser> ConvertResponseToUsers(List<Dictionary<string, AttributeValue>> response)
        {
            ConcurrentBag<TUser> users = new ConcurrentBag<TUser>();
            var userDict = response
                .Where(c => c["Id"].S.Equals(c["UserId"].S, StringComparison.OrdinalIgnoreCase));

            Parallel.ForEach<Dictionary<string, AttributeValue>>(userDict, (userItem) =>
            {
                //User
                TUser user = Context.FromDocument<TUser>(Document.FromAttributeMap(userItem));
                users.Add(MapResponseToUser(user, response));
            });
            return users;
        }

        private TUser ConvertResponseToUser(List<Dictionary<string, AttributeValue>> response)
        {
            //Fixes issue where OAuth user has not created a local account, not finding the PasswordHash field.
            var userDict = response
                .FirstOrDefault(c => c["Id"].S.Equals(c["UserId"].S, StringComparison.OrdinalIgnoreCase)); 

            if (userDict != null)
            {
                //User
                TUser user = Context.FromDocument<TUser>(Document.FromAttributeMap(userDict));
                return MapResponseToUser(user, response);
            }
            return null;
        }

        private TUserLogin ConvertResponseToUserLogin(List<Dictionary<string, AttributeValue>> response)
        {
            if (response.Any())
            {
                var userDict = response.First();

                if (userDict != null)
                {
                    TUserLogin userLogin = Context.FromDocument<TUserLogin>(Document.FromAttributeMap(userDict));
                    return userLogin;
                }
            }
            return null;
        }

        private IEnumerable<TUserRole> ConvertResponseToUserRoles(List<Dictionary<string, AttributeValue>> response)
        {
            ConcurrentBag<TUserRole> userRoles = new ConcurrentBag<TUserRole>();

            Parallel.ForEach<Dictionary<string, AttributeValue>>(response, (userItem) =>
            {
                //User
                TUserRole userRole = Context.FromDocument<TUserRole>(Document.FromAttributeMap(userItem));
                userRoles.Add(userRole);
            });
            return userRoles;
        }

        private TUser MapResponseToUser(TUser user, List<Dictionary<string, AttributeValue>> response)
        {
            //Claims
            response
                .Where(c => c.ContainsKey("ClaimType")
                    && c.ContainsKey("UserId")
                    && c["UserId"].S.Equals(user.UserId.ToString(), StringComparison.OrdinalIgnoreCase))
                .Select(c => Context.FromDocument<TUserClaim>(Document.FromAttributeMap(c)))
                .ToList()
                .ForEach(uc => { user.Claims.Add(uc); });

            //Logins
            response
                .Where(c => c.ContainsKey("LoginProvider")
                    && c.ContainsKey("UserId")
                    && c["UserId"].S.Equals(user.UserId.ToString(), StringComparison.OrdinalIgnoreCase))
                .Select(c => Context.FromDocument<TUserLogin>(Document.FromAttributeMap(c)))
                .ToList()
                .ForEach(l => { user.Logins.Add(l); });

            //Roles
            response
                .Where(c => c.ContainsKey("RoleName")
                    && c.ContainsKey("UserId")
                    && c["UserId"].S.Equals(user.UserId.ToString(), StringComparison.OrdinalIgnoreCase))
                .Select(c => Context.FromDocument<TUserRole>(Document.FromAttributeMap(c)))
                .ToList()
                .ForEach(r => { user.Roles.Add(r); });


            return user;
        }

        public virtual async Task<TUser> FindByNameAsync(string userName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            return await Context.Client.QueryAsync(new QueryRequest()
            {
                TableName = Context.FormatTableNameWithPrefix(Constants.TableNames.UsersTable),
                IndexName = Constants.SecondaryIndexNames.UserNameIndex,
                KeyConditions = new Dictionary<string, Condition>()
                { 
                    {"NormalizedUserName", new Condition()
                        { 
                            ComparisonOperator = ComparisonOperator.EQ,
                            AttributeValueList = new List<AttributeValue>() { new AttributeValue() { S = userName }}
                        }
                    }
                }
            }, cancellationToken)
            .ContinueWith<TUser>(new Func<Task<QueryResponse>, TUser>(
                (qResponse) => ConvertResponseToUser(qResponse.Result.Items)),
                cancellationToken);

        }

        public virtual async Task<TUser> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            var userLogin = await Context.Client.QueryAsync(new QueryRequest()
            {
                TableName = Context.FormatTableNameWithPrefix(Constants.TableNames.UserLoginsTable),
                IndexName = Constants.SecondaryIndexNames.UserLoginProviderKeyIndex,
                KeyConditions = new Dictionary<string, Condition>()
                {
                    {"LoginProviderPartitionKey", new Condition()
                        {
                            ComparisonOperator = ComparisonOperator.EQ,
                            AttributeValueList = new List<AttributeValue>() { new AttributeValue() { S = IdentityUserLogin.BuildLoginProviderPartitionKey(loginProvider, providerKey)}}
                        }
                    }
                }
            }, cancellationToken)
            .ContinueWith(new Func<Task<QueryResponse>, TUserLogin>(
                (qResponse) => ConvertResponseToUserLogin(qResponse.Result.Items)),
                cancellationToken);

            if (userLogin == null)
            {
                return null;
            }

            return await FindByIdAsync(userLogin.UserId, cancellationToken);
        }

        public Task<int> GetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return Task.FromResult<int>(user.AccessFailedCount);
        }

        public virtual Task<IList<Claim>> GetClaimsAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return Task.FromResult<IList<Claim>>(user.Claims.Select(c => new Claim(c.ClaimType, c.ClaimValue)).ToList());
        }

        public async Task<string> GetNormalizedEmailAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            var name = await GetEmailAsync(user, cancellationToken);

            return NormalizeEmail(name);
        }

        public Task SetNormalizedEmailAsync(TUser user, string email, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            user.NormalizedEmail = email;

            return Task.CompletedTask;
        }


        public Task<string> GetEmailAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return Task.FromResult<string>(user.Email);
        }

        public Task<string> GetUserIdAsync(TUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.Id);
        }

        public Task<string> GetUserNameAsync(TUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(user.UserName);
        }

        public async Task<string> GetNormalizedUserNameAsync(TUser user, CancellationToken cancellationToken)
        {
            var name = await GetUserNameAsync(user, cancellationToken);
            return Normalize(name);
        }

        public Task<bool> GetEmailConfirmedAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return Task.FromResult<bool>(user.EmailConfirmed);
        }

        public Task<bool> GetLockoutEnabledAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return Task.FromResult<bool>(user.LockoutEnabled);
        }

        public Task<DateTimeOffset?> GetLockoutEndDateAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            Func<DateTimeOffset> funcDt = () =>
                {
                    if(user.LockoutEndDateUtc.HasValue)
                    {
                        if(user.LockoutEndDateUtc.Value.Kind != DateTimeKind.Utc)
                        {
                            return new DateTimeOffset(DateTime.SpecifyKind(user.LockoutEndDateUtc.Value.ToUniversalTime(), DateTimeKind.Utc));
                        }
                        return new DateTimeOffset(DateTime.SpecifyKind(user.LockoutEndDateUtc.Value, DateTimeKind.Utc));

                    }
                    return new DateTimeOffset();
                };
            return Task.FromResult<DateTimeOffset?>(funcDt());
        }

        public virtual Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return Task.FromResult<IList<UserLoginInfo>>((from l in user.Logins select new UserLoginInfo(l.LoginProvider, l.ProviderKey, l.UserName)).ToList<UserLoginInfo>());
        }

        public Task<string> GetPasswordHashAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return Task.FromResult<string>(user.PasswordHash);
        }

        public Task<string> GetPhoneNumberAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return Task.FromResult<string>(user.PhoneNumber);
        }

        public Task<bool> GetPhoneNumberConfirmedAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return Task.FromResult<bool>(user.PhoneNumberConfirmed);
        }

        public virtual Task<IList<string>> GetRolesAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult<IList<string>>(user.Roles.ToList().Select(r => r.RoleName).ToList());
        }

        public Task<string> GetSecurityStampAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return Task.FromResult<string>(user.SecurityStamp);
        }

        public Task<bool> GetTwoFactorEnabledAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            return Task.FromResult<bool>(user.TwoFactorEnabled);
        }

        public Task<IList<TUser>> GetUsersInRoleAsync(string roleId, CancellationToken cancellationToken)
        {
            throw new NotSupportedException();
        }

        public Task<IList<TUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken)
        {
            throw new NotSupportedException();
        }

        public Task<bool> HasPasswordAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult<bool>(user.PasswordHash != null);
        }

        public Task<int> IncrementAccessFailedCountAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            user.AccessFailedCount++;
            return Task.FromResult<int>(user.AccessFailedCount);
        }

        public virtual Task<bool> IsInRoleAsync(TUser user, string roleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (string.IsNullOrWhiteSpace(roleName))
            {
                throw new ArgumentException(IdentityResources.ValueCannotBeNullOrEmpty, nameof(roleName));
            }

            return Task.FromResult<bool>(user.Roles.Any(r=> r.Id.ToString() == KeyHelper.GenerateRowKeyIdentityUserRole(roleName)));
        }

        public virtual async Task ReplaceClaimAsync(TUser user, Claim claim, Claim newClaim,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }
            if (string.IsNullOrWhiteSpace(claim.Type))
            {
                throw new ArgumentException(IdentityResources.ValueCannotBeNullOrEmpty, "claim.Type");
            }

            if (newClaim == null)
            {
                throw new ArgumentNullException(nameof(newClaim));
            }
            if (string.IsNullOrWhiteSpace(newClaim.Type))
            {
                throw new ArgumentException(IdentityResources.ValueCannotBeNullOrEmpty, "newClaim.Type");
            }

            BatchWriteItemRequest batchWriteReq = new BatchWriteItemRequest();
            batchWriteReq.RequestItems = new Dictionary<string, List<WriteRequest>>(1);
            List<WriteRequest> userClaimsWr = new List<WriteRequest>(2);

            TUserClaim local = (from uc in user.Claims
                                where uc.Id.ToString() == KeyHelper.GenerateRowKeyIdentityUserClaim(claim.Type, claim.Value)
                                select uc).FirstOrDefault();
            if (local != null)
            {
                user.Claims.Remove(local);
                var wr = CreateDeleteRequestForUserClaim(local.UserId, local.Id);
                userClaimsWr.Add(wr);
            }
            
            TUserClaim item = Activator.CreateInstance<TUserClaim>();
            item.UserId = user.UserId;
            item.ClaimType = claim.Type;
            item.ClaimValue = claim.Value;
            item.UserName = user.UserName;
            item.Email = user.Email;
            ((IGenerateKeys)item).GenerateKeys();


            user.Claims.Add(item);
            var putWr = CreatePutRequestForUserClaim(item);
            userClaimsWr.Add(putWr);

            
            batchWriteReq.RequestItems.Add(Context.FormatTableNameWithPrefix(Constants.TableNames.UserClaimsTable), userClaimsWr);
            

            var tresult = await Context.Client.BatchWriteItemAsync(batchWriteReq, cancellationToken);

            if (tresult.UnprocessedItems.Count > 0)
            {
                logger.LogWarning($"failed to completely replace user claims: {tresult.UnprocessedItems.Count} unprocessed requests");
            }
        }

        public virtual async Task RemoveClaimAsync(TUser user, Claim claim, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }

            if (string.IsNullOrWhiteSpace(claim.Type))
            {
                throw new ArgumentException(IdentityResources.ValueCannotBeNullOrEmpty, "claim.Type");
            }

            // Claim ctor doesn't allow Claim.Value to be null. Need to allow string.empty.

                   
            TUserClaim local = (from uc in user.Claims
                                where uc.Id.ToString() == KeyHelper.GenerateRowKeyIdentityUserClaim(claim.Type, claim.Value)
                                select uc).FirstOrDefault();
            if(local != null)
            {
                user.Claims.Remove(local);
                await Context.DeleteAsync<TUserClaim>(local, new DynamoDBOperationConfig()
                {
                    TableNamePrefix = Context.TablePrefix,
                    ConsistentRead = true,
                }, cancellationToken);
            }
        }

        public virtual async Task RemoveClaimsAsync(TUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (claims == null)
            {
                throw new ArgumentNullException(nameof(claims));
            }

            await Task.WhenAll(claims.Select(claim => RemoveClaimAsync(user, claim, cancellationToken)));
        }

        public virtual async Task RemoveFromRoleAsync(TUser user, string roleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (string.IsNullOrWhiteSpace(roleName))
            {
                throw new ArgumentException(IdentityResources.ValueCannotBeNullOrEmpty, nameof(roleName));
            }
            TUserRole item = user.Roles.FirstOrDefault<TUserRole>(r => r.Id.ToString() == KeyHelper.GenerateRowKeyIdentityUserRole(roleName));
            if (item != null)
            {
                user.Roles.Remove(item);
                await Context.DeleteAsync<TUserRole>(item, new DynamoDBOperationConfig()
                {
                    TableNamePrefix = Context.TablePrefix,
                    ConsistentRead = true,
                }, cancellationToken);
            }
        }

        public virtual async Task RemoveLoginAsync(TUser user, string loginProvider, string providerKey,
            CancellationToken cancellationToken)
        {
            await RemoveLoginAsync(user, new UserLoginInfo(loginProvider, providerKey, null), cancellationToken);
        }

        public virtual async Task RemoveLoginAsync(TUser user, UserLoginInfo login, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            if (login == null)
            {
                throw new ArgumentNullException(nameof(login));
            }

            BatchWriteItemRequest batchWriteReq = new BatchWriteItemRequest();
            batchWriteReq.RequestItems = new Dictionary<string, List<WriteRequest>>(10);
            List<WriteRequest> listUserwr = new List<WriteRequest>(10);
            List<WriteRequest> listIndexwr = new List<WriteRequest>(10);
            foreach (TUserLogin local in (from uc in user.Logins.ToList()
                                            where uc.Id.ToString() == KeyHelper.GenerateRowKeyUserLoginInfo(login)
                                            select uc))
            {
                var wr = CreateDeleteRequestForUser(local.UserId, local.Id);
                user.Logins.Remove(local);
                listUserwr.Add(wr);

                var iwr = CreateDeleteRequestForIndex(local.Id);
                listIndexwr.Add(iwr);
            }
            batchWriteReq.RequestItems.Add(Context.FormatTableNameWithPrefix(Constants.TableNames.UsersTable), listUserwr);
            batchWriteReq.RequestItems.Add(Context.FormatTableNameWithPrefix(Constants.TableNames.IndexTable), listIndexwr);

            if (listUserwr.Count > 0)
            {
                var tresult = await Context.Client.BatchWriteItemAsync(batchWriteReq, cancellationToken);
            }

        }

        public Task ResetAccessFailedCountAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            user.AccessFailedCount = 0;
            return Task.FromResult<int>(0);
        }

        public Task SetNormalizedUserNameAsync(TUser user, string userName, CancellationToken cancellationToken)
        {
            this.ThrowIfDisposed();
            cancellationToken.ThrowIfCancellationRequested();
            if (userName == null)
            {
                throw new ArgumentNullException(nameof(userName));
            }

            user.NormalizedUserName = userName;
            return Task.CompletedTask;
        }

        public async Task SetUserNameAsync(TUser user, string userName, CancellationToken cancellationToken)
        {
            this.ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            //Only remove the email if different
            if (string.IsNullOrWhiteSpace(user.Email) ||
                !user.Email.Equals(userName ?? string.Empty, StringComparison.OrdinalIgnoreCase))
            {
                var itemUpdates = CreateUserNameUpdateRequests(user, userName);
                var tasks = new List<Task>(itemUpdates.Count);
                foreach (var updRequest in itemUpdates)
                {
                    updRequest.TableName = Context.FormatTableNameWithPrefix(Constants.TableNames.UsersTable);
                    tasks.Add(Context.Client.UpdateItemAsync(updRequest, cancellationToken));
                }
                await Task.WhenAll(tasks.ToArray());
            }
            user.UserName = userName;
        }

        public async Task SetEmailAsync(TUser user, string email, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (email != null)
            {
                email = email.Trim();
                if (email.Length == 0)
                {
                    email = null;
                }
            }

            //Only remove the email if different
            if (string.IsNullOrWhiteSpace(user.Email) ||
                !user.Email.Equals(email?? string.Empty, StringComparison.OrdinalIgnoreCase))
            {
                var itemUpdates = CreateEmailUpdateRequests(user, email);
                List<Task> tasks = new List<Task>(itemUpdates.Count);
                foreach (var updRequest in itemUpdates)
                {
                    updRequest.TableName = Context.FormatTableNameWithPrefix(Constants.TableNames.UsersTable);
                    tasks.Add(Context.Client.UpdateItemAsync(updRequest));
                }
                await Task.WhenAll(tasks.ToArray());
            }
            user.Email = email;
        }

        private List<UpdateItemRequest> CreateEmailUpdateRequests(TUser user, string emailNew)
        {
            List<UpdateItemRequest> list = new List<UpdateItemRequest>(200);
            list.Add(CreateEmailUpdateRequest(new Dictionary<string,AttributeValue>() 
            { 
                { "UserId", new AttributeValue() { S = user.UserId.ToString() } }, 
                { "Id", new AttributeValue(){S = user.Id.ToString()} } 
            }, emailNew));
            user.Roles.ToList().ForEach(r =>
            {
                list.Add(CreateEmailUpdateRequest(new Dictionary<string, AttributeValue>() 
                { 
                    { "UserId", new AttributeValue() { S = r.UserId.ToString() } }, 
                    { "Id", new AttributeValue(){S = r.Id.ToString()} } 
                }, emailNew));
            });
            user.Claims.ToList().ForEach(c =>
            {
                list.Add(CreateEmailUpdateRequest(new Dictionary<string, AttributeValue>() 
                { 
                    { "UserId", new AttributeValue() { S = c.UserId.ToString() } }, 
                    { "Id", new AttributeValue(){S = c.Id.ToString()} } 
                }, emailNew));
            });
            user.Logins.ToList().ForEach(l =>
            {
                list.Add(CreateEmailUpdateRequest(new Dictionary<string, AttributeValue>() 
                { 
                    { "UserId", new AttributeValue() { S = l.UserId.ToString() } }, 
                    { "Id", new AttributeValue(){S = l.Id.ToString()} } 
                }, emailNew));
            });

            return list;
        }

        private UpdateItemRequest CreateEmailUpdateRequest(Dictionary<string,AttributeValue> key, string emailNew)
        {
            var userwr = new UpdateItemRequest();
            userwr.AttributeUpdates = new Dictionary<string, AttributeValueUpdate>();
            if (string.IsNullOrWhiteSpace(emailNew))
            {
                userwr.AttributeUpdates.Add("Email", new AttributeValueUpdate() 
                { Action = Amazon.DynamoDBv2.AttributeAction.DELETE });
            }
            else
            {
                userwr.AttributeUpdates.Add("Email", new AttributeValueUpdate()
                {
                    Action = Amazon.DynamoDBv2.AttributeAction.PUT,
                    Value = new AttributeValue() { S = emailNew }
                });
            }
            userwr.Key = key;
            return userwr;
        }

        public Task SetEmailConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            user.EmailConfirmed = confirmed;
            return Task.FromResult<int>(0);
        }

        public Task SetLockoutEnabledAsync(TUser user, bool enabled, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            user.LockoutEnabled = enabled;
            return Task.FromResult<int>(0);
        }

        public Task SetLockoutEndDateAsync(TUser user, DateTimeOffset? lockoutEnd, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            user.LockoutEndDateUtc = (!lockoutEnd.HasValue || lockoutEnd == DateTimeOffset.MinValue) ? null : new DateTime?(lockoutEnd.Value.UtcDateTime);
            return Task.FromResult<int>(0);
        }

        public Task SetPasswordHashAsync(TUser user, string passwordHash, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            user.PasswordHash = passwordHash;
            return Task.FromResult<int>(0);
        }

        public Task SetPhoneNumberAsync(TUser user, string phoneNumber, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            user.PhoneNumber = phoneNumber;
            return Task.FromResult<int>(0);
        }

        public Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            user.PhoneNumberConfirmed = confirmed;
            return Task.FromResult<int>(0);
        }

        public Task SetSecurityStampAsync(TUser user, string stamp, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            user.SecurityStamp = stamp;
            return Task.FromResult<int>(0);
        }

        public Task SetTwoFactorEnabledAsync(TUser user, bool enabled, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            user.TwoFactorEnabled = enabled;
            return Task.FromResult<int>(0);
        }

        private void ThrowIfDisposed()
        {
            if (this._disposed)
            {
                throw new ObjectDisposedException(base.GetType().Name);
            }
        }

        public virtual async Task<IdentityResult> UpdateAsync(TUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            try
            {
                //Change user name on roles, logins and claims, if different
                var itemUpdates = CreateUserNameUpdateRequests(user, user.UserName);
                List<Task> tasks = new List<Task>(itemUpdates.Count + 1);

                if (itemUpdates.Count > 0) //Only attempt username change if any differences found.
                {
                    foreach (var updRequest in itemUpdates)
                    {
                        updRequest.TableName = Context.FormatTableNameWithPrefix(Constants.TableNames.UsersTable);
                        tasks.Add(Context.Client.UpdateItemAsync(updRequest, cancellationToken));
                    }
                }
                tasks.Add(Context.SaveAsync<TUser>(user, new DynamoDBOperationConfig()
                {
                    TableNamePrefix = this.Context.TablePrefix,
                    ConsistentRead = true
                }, cancellationToken));

                await Task.WhenAll(tasks);
                user.Roles.ToList().ForEach(r => r.UserName = user.UserName);
                user.Claims.ToList().ForEach(c => c.UserName = user.UserName);
                user.Logins.ToList().ForEach(l => l.UserName = user.UserName);
            }
            catch (Exception e)
            {
                logger.LogInformation($"error updating user {user}: {e}");
                return IdentityResult.Failed(new IdentityErrorDescriber().DefaultError());
            }
            
            return IdentityResult.Success;
        }

        /// <summary>
        /// Create updates for any roles, claims and/or logins that don't have the username passed in.
        /// </summary>
        /// <param name="user">User containing updates.</param>
        /// <param name="userNameNew">The 'new' username to check against. </param>
        /// <returns></returns>
        private List<UpdateItemRequest> CreateUserNameUpdateRequests(TUser user, string userNameNew)
        {
            List<UpdateItemRequest> list = new List<UpdateItemRequest>(200);
            user.Roles.Where(x => !x.UserName.Equals(userNameNew, StringComparison.OrdinalIgnoreCase)).ToList().ForEach(r =>
            {
                list.Add(CreateUserNameUpdateRequest(new Dictionary<string, AttributeValue>() 
                { 
                    { "UserId", new AttributeValue() { S = r.UserId.ToString() } }, 
                    { "Id", new AttributeValue(){S = r.Id.ToString()} } 
                }, userNameNew));
            });
            user.Claims.Where(x => !x.UserName.Equals(userNameNew, StringComparison.OrdinalIgnoreCase)).ToList().ForEach(c =>
            {
                list.Add(CreateUserNameUpdateRequest(new Dictionary<string, AttributeValue>() 
                { 
                    { "UserId", new AttributeValue() { S = c.UserId.ToString() } }, 
                    { "Id", new AttributeValue(){S = c.Id.ToString()} } 
                }, userNameNew));
            });
            user.Logins.Where(x => !x.UserName.Equals(userNameNew, StringComparison.OrdinalIgnoreCase)).ToList().ForEach(l =>
            {
                list.Add(CreateUserNameUpdateRequest(new Dictionary<string, AttributeValue>() 
                { 
                    { "UserId", new AttributeValue() { S = l.UserId.ToString() } }, 
                    { "Id", new AttributeValue(){S = l.Id.ToString()} } 
                }, userNameNew));
            });

            return list;
        }

        private UpdateItemRequest CreateUserNameUpdateRequest(Dictionary<string, AttributeValue> key, string userNameNew)
        {
            var userwr = new UpdateItemRequest();
            userwr.AttributeUpdates = new Dictionary<string, AttributeValueUpdate>();
            userwr.AttributeUpdates.Add("UserName", new AttributeValueUpdate()
            {
                Action = Amazon.DynamoDBv2.AttributeAction.PUT,
                Value = new AttributeValue() { S = userNameNew }
            });
            userwr.Key = key;
            return userwr;
        }

        private WriteRequest CreatePutRequestForUserClaim(IdentityUserClaim userClaim)
        {
            var wr = new WriteRequest();
            var claimwr = new PutRequest();
            claimwr.Item = new Dictionary<string, AttributeValue>
            {
                {"UserId", new AttributeValue() { S = userClaim.UserId }},
                {"Id", new AttributeValue() { S = userClaim.Id }},
                {"UserName", new AttributeValue() { S = userClaim.UserName }},
                {"Email", new AttributeValue() { S = userClaim.Email }},
                {"ClaimType", new AttributeValue() { S = userClaim.ClaimType }},
                {"ClaimValue", new AttributeValue() { S = userClaim.ClaimValue }},
            };
            wr.PutRequest = claimwr;
            return wr;
        }

        protected virtual string NormalizeEmail(string emailAddress)
        {
            if (string.IsNullOrWhiteSpace(emailAddress))
            {
                return emailAddress;
            }

            var addr = new MailAddress(emailAddress.Trim());

            var normalizedHostname = new UpperInvariantLookupNormalizer().Normalize(addr.Host);

            var normalizedAddress = $"{addr.User}@{normalizedHostname}";

            return normalizedAddress;
        }

        protected virtual string Normalize(string str)
        {
            if (string.IsNullOrWhiteSpace(str)) return str;
            return new UpperInvariantLookupNormalizer().Normalize(str);
        }

        public IdentityCloudContext<TUser, TRole, string, TUserLogin, TUserRole, TUserClaim> Context { get; private set; }


        public IQueryable<TUser> Users
        {
            get
            {
                ThrowIfDisposed();
                return _users;
            }
        }
    }
}
