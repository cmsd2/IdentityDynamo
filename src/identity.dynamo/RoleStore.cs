// MIT License Copyright 2014 (c) David Melendez. All rights reserved. See License.txt in the project root for license information.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using System.Net;
using System.Diagnostics;
using System.Threading;
using ElCamino.AspNet.Identity.Dynamo.Model;
using ElCamino.AspNet.Identity.Dynamo.Helpers;
using Amazon.DynamoDBv2.DocumentModel;
using Amazon.DynamoDBv2.DataModel;
using Microsoft.Extensions.Logging;

namespace ElCamino.AspNet.Identity.Dynamo
{
    public class RoleStore<TRole> : RoleStore<TRole, IdentityUserRole>, IQueryableRoleStore<TRole>, IRoleStore<TRole> where TRole : IdentityRole, new()
    {
        public RoleStore(ILoggerFactory loggerFactory)
            : this(loggerFactory, new IdentityCloudContext())
        {
            
        }

        public RoleStore(ILoggerFactory loggerFactory, IdentityCloudContext context)
            : base(loggerFactory, context) { }

        //Fixing code analysis issue CA1063
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
        }
    }

    public class RoleStore<TRole, TUserRole> : IQueryableRoleStore<TRole>, IRoleStore<TRole>, IDisposable
        where TRole : IdentityRole<string, TUserRole>, new()
        where TUserRole : IdentityUserRole<string>, new()
    {
        private bool _disposed;
        private readonly ILogger _logger;

        public RoleStore(ILoggerFactory loggerFactory, IdentityCloudContext<IdentityUser, IdentityRole, string, IdentityUserLogin, IdentityUserRole, IdentityUserClaim> context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context));
            }
            this._logger = loggerFactory.CreateLogger("RoleStore");
            this.Context = context;
        }

        public async Task CreateTableIfNotExistsAsync()
        {
            await Context.CreateRoleTableAsync();
        }

        public virtual async Task<IdentityResult> CreateAsync(TRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            ((IGenerateKeys)role).GenerateKeys();


            try
            {
                await Context.SaveAsync<TRole>(role, new DynamoDBOperationConfig()
                {
                    TableNamePrefix = Context.TablePrefix,
                    ConsistentRead = true,
                }, cancellationToken);
            }
            catch (Exception e)
            {
                _logger.LogInformation($"error saving role: {e}");
                return IdentityResult.Failed(new IdentityErrorDescriber().DefaultError());
            }

            return IdentityResult.Success;
        }

        public virtual async Task<IdentityResult> DeleteAsync(TRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            try
            {
                await Context.DeleteAsync<TRole>(role, new DynamoDBOperationConfig()
                {
                    TableNamePrefix = Context.TablePrefix,
                    ConsistentRead = true,
                }, cancellationToken);
            }
            catch (Exception e)
            {
                _logger.LogInformation($"error deleting role: {e}");
                return IdentityResult.Failed(new IdentityErrorDescriber().DefaultError());
            }
            

            return IdentityResult.Success;
        }

        public Task<string> GetRoleIdAsync(TRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            return Task.FromResult(role.Id);
        }

        public Task<string> GetRoleNameAsync(TRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            return Task.FromResult(role.Name);
        }

        public async Task SetRoleNameAsync(TRole role, string roleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            role.Name = roleName;
            await CreateAsync(role, cancellationToken);
        }

        public async Task<string> GetNormalizedRoleNameAsync(TRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            var name = await GetRoleNameAsync(role, cancellationToken);

            return Normalize(name);
        }

        public Task SetNormalizedRoleNameAsync(TRole role, string name, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            var normalizedName = Normalize(name);

            return SetRoleNameAsync(role, normalizedName, cancellationToken);
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
                if (Context != null)
                {
                    Context.Dispose();
                }
                _disposed = true;
                Context = null;
            }
        }

        public async Task<TRole> FindByIdAsync(string roleId, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            return await FindIdAsync(roleId.ToString(), cancellationToken);
        }

        public async Task<TRole> FindByNameAsync(string roleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            return await FindIdAsync(KeyHelper.GenerateRowKeyIdentityRole(roleName), cancellationToken);
        }

        private Task<TRole> FindIdAsync(string roleId, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();
            
            return Context.LoadAsync<TRole>(roleId, new DynamoDBOperationConfig()
                {
                    TableNamePrefix = Context.TablePrefix,
                    ConsistentRead = true,
                }, cancellationToken);
        }

        private void ThrowIfDisposed()
        {
            if (this._disposed)
            {
                throw new ObjectDisposedException(base.GetType().Name);
            }
        }

        public virtual async Task<IdentityResult> UpdateAsync(TRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }
            
            try
            {
                var batchWrite = Context.CreateBatchWrite<TRole>(new DynamoDBOperationConfig()
                {
                    TableNamePrefix = Context.TablePrefix,
                    ConsistentRead = true,
                });

                var g = role as IGenerateKeys;
                if (!g.PeekRowKey().Equals(role.Id.ToString(), StringComparison.Ordinal))
                {
                    batchWrite.AddDeleteKey(role.Id.ToString());
                }
                g.GenerateKeys();
                batchWrite.AddPutItem(role);

                await Context.ExecuteBatchWriteAsync(new BatchWrite[] {batchWrite}, cancellationToken);
            }
            catch (Exception e)
            {
                _logger.LogInformation($"error updating role: {e}");
                return IdentityResult.Failed(new IdentityErrorDescriber().DefaultError());
            }

            return IdentityResult.Success;
        }

        public IdentityCloudContext<IdentityUser, IdentityRole, string, IdentityUserLogin, IdentityUserRole, IdentityUserClaim> Context { get; private set; }

        /// <summary>
        /// Changing from NotImplemented exception to NotSupported to avoid code analysis message.
        /// </summary>
        public IQueryable<TRole> Roles
        {
            get
            {
                throw new NotSupportedException();
            }
        }

        protected virtual string Normalize(string str)
        {
            if (string.IsNullOrWhiteSpace(str)) return str;
            return str.ToLower().Trim();
        }

    }
}
