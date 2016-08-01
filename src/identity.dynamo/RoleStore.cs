﻿// MIT License Copyright 2014 (c) David Melendez. All rights reserved. See License.txt in the project root for license information.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using System.Net;
using System.Diagnostics;
using ElCamino.AspNet.Identity.Dynamo.Model;
using ElCamino.AspNet.Identity.Dynamo.Helpers;
using Amazon.DynamoDBv2.DocumentModel;
using Amazon.DynamoDBv2.DataModel;

namespace ElCamino.AspNet.Identity.Dynamo
{
    public class RoleStore<TRole> : RoleStore<TRole, string, IdentityUserRole>, IQueryableRoleStore<TRole>, IQueryableRoleStore<TRole, string>, IRoleStore<TRole, string> where TRole : IdentityRole, new()
    {
        public RoleStore()
            : this(new IdentityCloudContext())
        {
            
        }

        public RoleStore(IdentityCloudContext context)
            : base(context) { }

        //Fixing code analysis issue CA1063
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
        }
    }

    public class RoleStore<TRole, TKey, TUserRole> : IQueryableRoleStore<TRole, TKey>, IRoleStore<TRole, TKey>, IDisposable
        where TRole : IdentityRole<TKey,TUserRole>, new()
        where TUserRole : IdentityUserRole<TKey>, new()
    {
        private bool _disposed;

        public RoleStore(IdentityCloudContext<IdentityUser, IdentityRole, string, IdentityUserLogin, IdentityUserRole, IdentityUserClaim> context)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }
            this.Context = context;
        }

        public async Task CreateTableIfNotExistsAsync()
        {
            await Context.CreateRoleTableAsync();
        }

        public async virtual Task CreateAsync(TRole role)
        {
            ThrowIfDisposed();
            if (role == null)
            {
                throw new ArgumentNullException("role");
            }

            ((IGenerateKeys)role).GenerateKeys();

            await Context.SaveAsync<TRole>(role, new DynamoDBOperationConfig()
            {
                TableNamePrefix = Context.TablePrefix,
                ConsistentRead = true,
            });

        }

        public async virtual Task DeleteAsync(TRole role)
        {
            ThrowIfDisposed();
            if (role == null)
            {
                throw new ArgumentNullException("role");
            }
            await Context.DeleteAsync<TRole>(role, new DynamoDBOperationConfig()
            {
                TableNamePrefix = Context.TablePrefix,
                ConsistentRead = true,
            });

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

        public async Task<TRole> FindByIdAsync(TKey roleId)
        {
            this.ThrowIfDisposed();
            return await FindIdAsync(roleId.ToString());
        }

        public async Task<TRole> FindByNameAsync(string roleName)
        {
            this.ThrowIfDisposed();
            return await FindIdAsync(KeyHelper.GenerateRowKeyIdentityRole(roleName));
        }

        private Task<TRole> FindIdAsync(string roleId)
        {
            return Context.LoadAsync<TRole>(roleId, new DynamoDBOperationConfig()
                {
                    TableNamePrefix = Context.TablePrefix,
                    ConsistentRead = true,
                });
        }

        private void ThrowIfDisposed()
        {
            if (this._disposed)
            {
                throw new ObjectDisposedException(base.GetType().Name);
            }
        }

        public async virtual Task UpdateAsync(TRole role)
        {
            ThrowIfDisposed();
            if (role == null)
            {
                throw new ArgumentNullException("role");
            }

            var batchWrite = Context.CreateBatchWrite<TRole>(new DynamoDBOperationConfig()
            {
                TableNamePrefix = Context.TablePrefix,
                ConsistentRead = true,
            });
           
            IGenerateKeys g = role as IGenerateKeys;
            if (!g.PeekRowKey().Equals(role.Id.ToString(), StringComparison.Ordinal))
            {
                batchWrite.AddDeleteKey(role.Id.ToString());
            }
            g.GenerateKeys();
            batchWrite.AddPutItem(role);
            await Context.ExecuteBatchWriteAsync(new BatchWrite[] { batchWrite });
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

    }
}
