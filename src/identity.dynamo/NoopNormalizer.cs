using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;

namespace ElCamino.AspNet.Identity.Dynamo
{
    public class NoopNormalizer : ILookupNormalizer
    {
        public string Normalize(string key)
        {
            return key;
        }
    }
}
