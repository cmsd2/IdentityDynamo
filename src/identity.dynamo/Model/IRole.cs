using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ElCamino.AspNet.Identity.Dynamo.Model
{
    //
    // Summary:
    //     Mimimal set of data needed to persist role information
    //
    // Type parameters:
    //   TKey:
    public interface IRole<out TKey>
    {
        //
        // Summary:
        //     Id of the role
        TKey Id { get; }
        //
        // Summary:
        //     Name of the role
        string Name { get; set; }
    }

    //
    // Summary:
    //     Mimimal set of data needed to persist role information
    public interface IRole : IRole<string>
    {
    }
}
