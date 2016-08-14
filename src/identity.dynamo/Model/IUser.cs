using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ElCamino.AspNet.Identity.Dynamo.Model
{
    //
    // Summary:
    //     Minimal interface for a user with id and username
    //
    // Type parameters:
    //   TKey:
    public interface IUser<out TKey>
    {
        //
        // Summary:
        //     Unique key for the user
        TKey Id { get; }
        //
        // Summary:
        //     Unique username
        string UserName { get; set; }
    }

    public interface IUser : IUser<string>
    {
    }
}
