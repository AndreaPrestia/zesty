# Description #

**Zesty** was born with the aim of simplifying the development of web applications, allowing to adopt some practices that improve development and operations.

The **Zesty** solution contains the **Zesty.Core** project (the framework), **Zesty.Configuration** project (now with only MS-SQL Server scripts to generate the database and the a Requests.http file with system APIs), **Zesty.Microsoft.SqlServer** (the project that implements the interface **Zesty.Core.IStorage** for the storage) and **Zesty.Web** (a sample project).

To work **Zesty** needs a storage. The default storage is no more available on Zesty.Core project, but there is a Zesty.Microsoft.SqlServer project that implements the interface   **Zesty.Core.IStorage**. You can still implement the previous interface and configure the key *StorageType* in **appsettings.json** if you want use other technologies (i think i will experiment something with MongoDB or something similar).

Inside the **Zesty.Configuration.Scripts.SqlServer** directory there are 15 SQL scripts, with the order of execution as prefix.

## Usage ##

To create a Zesty-based project, you need to create a .NET Core Web Application (MVC) project and add a reference to **Zesty.Core** (if you want to implement your own storage in your web project) or, if you want the Sql Server storage just add a reference to **Zesty.Microsoft.SqlServer**.

Add the following section in the **appsettings.json** (with the reference to **Zesty.Microsoft.SqlServer**).

Be aware to edit the settings with your environment values.

```json
"Zesty": {
    "StorageImplementationType": "Zesty.Microsoft.SqlServer.Storage, Zesty.Microsoft.SqlServer",
    "StorageSource": "Data Source = 192.168.1.222; Initial Catalog = Zesty; User Id = zestyUser; Password = zesty.Password."
}

```

Add a file named **nlog.config**, set the build type as *Content*, set *Copy to output directory* and paste the following contents. 

Be aware to edit the settings with your environment values.

```xml
<?xml version="1.0" encoding="utf-8" ?>
<nlog xmlns="http://www.nlog-project.org/schemas/NLog.xsd"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      autoReload="true">

  <extensions>
    <add assembly="NLog.Web.AspNetCore"/>
  </extensions>

  <targets>
    <target 
            xsi:type="File" 
            name="logger" 
            fileName="/Users/eca/logs/zesty-web-${shortdate}.log"
            layout="${longdate} ${threadid} ${uppercase:${level}} ${logger} ${message} ${exception:format=tostring}" />
  </targets>

  <rules>
    <logger name="*" minlevel="Debug" writeTo="logger" />
  </rules>
</nlog>
```

In the **Startup.cs** file add this *using*

```c#
using Zesty.Core.Common;
```

In the **Startup.cs** file in the method *ConfigureServices* add this line of code
```c#
services.AddZesty();
```

In the **Startup.cs** file in the method *Configure* add this line of code
```c#
app.UseZesty();
```
If you want to use Zesty with classic .NET Core APIs add the following line in the beginning of method *Configure*

```c#
app.UseZestyError();
```

## TODO ##
