// sbit-dotnet — помощник анализатора StretchBIT для сборок .NET (только чтение файла,
// сборка не загружается и не запускается: метаданные читает ICSharpCode.Decompiler).
//   sbit-dotnet tree <файл>                 → JSON: сведения, пространства имён, типы, ресурсы
//   sbit-dotnet resources <файл> <папка>    → встроенные ресурсы в файлы, JSON со списком
//   sbit-dotnet decompile <файл> [тип]      → код C# типа (полное имя) или всей сборки
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Text;
using System.Text.Json;
using ICSharpCode.Decompiler;
using ICSharpCode.Decompiler.CSharp;
using ICSharpCode.Decompiler.Metadata;
using ICSharpCode.Decompiler.TypeSystem;

static class Program
{
    static int Main(string[] args)
    {
        Console.OutputEncoding = new UTF8Encoding(false);
        try
        {
            if (args.Length >= 2 && args[0] == "tree") return Tree(args[1]);
            if (args.Length >= 3 && args[0] == "resources") return Resources(args[1], args[2]);
            if (args.Length >= 2 && args[0] == "decompile")
                return Decompile(args[1], args.Length >= 3 ? args[2] : null);
            Console.Error.WriteLine("usage: sbit-dotnet tree|resources|decompile <file> ...");
            return 2;
        }
        catch (Exception e)
        {
            Console.Error.WriteLine(e.GetType().Name + ": " + e.Message);
            return 1;
        }
    }

    static PEFile Open(string path) =>
        new PEFile(path, new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite),
                   PEStreamOptions.PrefetchEntireImage, MetadataReaderOptions.Default);

    static CSharpDecompiler Decompiler(string path)
    {
        var module = Open(path);
        var resolver = new UniversalAssemblyResolver(path, false,
            module.Metadata.DetectTargetFrameworkId());
        var settings = new DecompilerSettings { ThrowOnAssemblyResolveErrors = false };
        return new CSharpDecompiler(module, resolver, settings);
    }

    static int Tree(string path)
    {
        var module = Open(path);
        var md = module.Metadata;
        var info = new Dictionary<string, object>();
        if (md.IsAssembly)
        {
            var asm = md.GetAssemblyDefinition();
            info["assembly"] = md.GetString(asm.Name);
            info["version"] = asm.Version.ToString();
        }
        info["module"] = module.Name;
        info["framework"] = md.DetectTargetFrameworkId() ?? "";
        info["references"] = md.AssemblyReferences
            .Select(h => md.GetString(md.GetAssemblyReference(h).Name)).ToList();

        var entry = module.Reader.PEHeaders.CorHeader?.EntryPointTokenOrRelativeVirtualAddress ?? 0;
        var types = new List<Dictionary<string, object>>();
        foreach (var h in md.TypeDefinitions)
        {
            var t = md.GetTypeDefinition(h);
            if (t.GetDeclaringType().IsNil == false) continue;   // вложенные — внутри родителя
            types.Add(TypeInfo(md, h, entry));
        }
        info["types"] = types;
        info["resources"] = module.Resources.Select(r => new Dictionary<string, object>
        {
            ["name"] = r.Name,
            ["kind"] = r.ResourceType.ToString(),
            ["size"] = r.TryGetLength() ?? -1,
        }).ToList();
        Console.Write(JsonSerializer.Serialize(info));
        return 0;
    }

    static Dictionary<string, object> TypeInfo(MetadataReader md, TypeDefinitionHandle h, int entry)
    {
        var t = md.GetTypeDefinition(h);
        var methods = new List<string>();
        bool hasEntry = false;
        foreach (var mh in t.GetMethods())
        {
            var m = md.GetMethodDefinition(mh);
            methods.Add(md.GetString(m.Name));
            if (MetadataTokens.GetToken(mh) == entry) hasEntry = true;
        }
        var flags = t.Attributes;
        string kind = (flags & System.Reflection.TypeAttributes.Interface) != 0 ? "interface" : "class";
        return new Dictionary<string, object>
        {
            ["namespace"] = md.GetString(t.Namespace),
            ["name"] = md.GetString(t.Name),
            ["full"] = FullName(md, h),
            ["kind"] = kind,
            ["methods"] = methods,
            ["fields"] = t.GetFields().Count,
            ["entry"] = hasEntry,
            ["nested"] = t.GetNestedTypes().Select(n => TypeInfo(md, n, entry)).ToList(),
        };
    }

    static string FullName(MetadataReader md, TypeDefinitionHandle h)
    {
        var t = md.GetTypeDefinition(h);
        var name = md.GetString(t.Name);
        var parent = t.GetDeclaringType();
        if (!parent.IsNil) return FullName(md, parent) + "+" + name;
        var ns = md.GetString(t.Namespace);
        return ns.Length > 0 ? ns + "." + name : name;
    }

    static int Resources(string path, string outDir)
    {
        var module = Open(path);
        Directory.CreateDirectory(outDir);
        var list = new List<Dictionary<string, object>>();
        int i = 0;
        foreach (var r in module.Resources)
        {
            if (r.ResourceType != ResourceType.Embedded) continue;
            using var s = r.TryOpenStream();
            if (s == null) continue;
            var safe = string.Concat(r.Name.Select(c => Path.GetInvalidFileNameChars().Contains(c) ? '_' : c));
            var file = Path.Combine(outDir, $"{i++:D3}_{safe}");
            using (var f = File.Create(file)) s.CopyTo(f);
            list.Add(new Dictionary<string, object> { ["name"] = r.Name, ["file"] = file });
        }
        Console.Write(JsonSerializer.Serialize(list));
        return 0;
    }

    static int Decompile(string path, string type)
    {
        var decompiler = Decompiler(path);
        string code = type == null
            ? decompiler.DecompileWholeModuleAsString()
            // вложенный тип: «Внешний+Вложенный» → «Внешний/Вложенный» (нотация FullTypeName)
            : decompiler.DecompileTypeAsString(new FullTypeName(type.Replace('+', '/')));
        Console.Write(code);
        return 0;
    }
}
