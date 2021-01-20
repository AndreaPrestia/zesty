﻿USE [Zesty]
GO
/****** Object:  Table [dbo].[Authorization]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Authorization](
	[UserId] [uniqueidentifier] NOT NULL,
	[DomainId] [uniqueidentifier] NOT NULL,
	[RoleId] [uniqueidentifier] NOT NULL,
 CONSTRAINT [PK_Authorization] PRIMARY KEY CLUSTERED 
(
	[UserId] ASC,
	[DomainId] ASC,
	[RoleId] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[ClientSetting]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[ClientSetting](
	[Key] [varchar](100) NOT NULL,
	[Value] [varchar](300) NOT NULL,
 CONSTRAINT [PK_ClientSetting] PRIMARY KEY CLUSTERED 
(
	[Key] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Domain]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Domain](
	[Id] [uniqueidentifier] NOT NULL,
	[ParentDomainId] [uniqueidentifier] NULL,
	[Name] [varchar](300) NOT NULL,
 CONSTRAINT [PK_Domain] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[History]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[History](
	[Id] [uniqueidentifier] NOT NULL,
	[Created] [datetime] NOT NULL,
	[UserId] [uniqueidentifier] NOT NULL,
	[Actor] [varchar](100) NOT NULL,
	[Resource] [varchar](300) NOT NULL,
	[Text] [varchar](max) NOT NULL,
 CONSTRAINT [PK_History] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Language]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Language](
	[Id] [int] NOT NULL,
	[Name] [varchar](50) NOT NULL,
	[Description] [varchar](100) NOT NULL,
	[Direction] [char](1) NOT NULL,
 CONSTRAINT [PK_Language] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Resource]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Resource](
	[Id] [uniqueidentifier] NOT NULL,
	[ParentId] [uniqueidentifier] NULL,
	[IsPublic] [bit] NOT NULL,
	[RequireToken] [bit] NOT NULL,
	[Order] [int] NULL,
	[Url] [varchar](400) NOT NULL,
	[Label] [varchar](50) NULL,
	[Image] [varchar](300) NULL,
	[Title] [varchar](100) NULL,
 CONSTRAINT [PK_Resource] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[ResourceRole]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[ResourceRole](
	[ResourceId] [uniqueidentifier] NOT NULL,
	[RoleId] [uniqueidentifier] NOT NULL,
 CONSTRAINT [PK_ResourceRole] PRIMARY KEY CLUSTERED 
(
	[ResourceId] ASC,
	[RoleId] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[ResourceType]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[ResourceType](
	[ResourceId] [uniqueidentifier] NOT NULL,
	[Type] [varchar](500) NOT NULL,
 CONSTRAINT [PK_ResourceType] PRIMARY KEY CLUSTERED 
(
	[ResourceId] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Role]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Role](
	[Id] [uniqueidentifier] NOT NULL,
	[Name] [varchar](200) NOT NULL,
 CONSTRAINT [PK_Role] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[ServerSetting]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[ServerSetting](
	[Id] [uniqueidentifier] NOT NULL,
	[Key] [varchar](200) NOT NULL,
	[Order] [int] NOT NULL,
	[Value] [varchar](500) NOT NULL,
 CONSTRAINT [PK_ServerSetting] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Token]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Token](
	[UserId] [uniqueidentifier] NOT NULL,
	[SessionId] [varchar](50) NOT NULL,
	[Value] [varchar](100) NOT NULL,
	[IsReusable] [bit] NOT NULL,
	[Created] [datetime] NOT NULL,
	[Deleted] [datetime] NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Translation]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Translation](
	[Id] [int] NOT NULL,
	[LanguageId] [int] NOT NULL,
	[Original] [varchar](500) NOT NULL,
	[Translated] [varchar](500) NOT NULL,
 CONSTRAINT [PK_Translation] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[User]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[User](
	[Id] [uniqueidentifier] NOT NULL,
	[Username] [varchar](200) NOT NULL,
	[Email] [varchar](200) NOT NULL,
	[Firstname] [varchar](50) NOT NULL,
	[Lastname] [varchar](50) NOT NULL,
	[ResetToken] [uniqueidentifier] NULL,
	[Deleted] [datetime] NULL,
	[Created] [datetime] NOT NULL,
 CONSTRAINT [PK_User] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[UserPassword]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[UserPassword](
	[Id] [uniqueidentifier] NOT NULL,
	[UserId] [uniqueidentifier] NOT NULL,
	[Password] [varchar](100) NOT NULL,
	[Deleted] [datetime] NULL,
	[Created] [datetime] NOT NULL,
 CONSTRAINT [PK_UserPassword] PRIMARY KEY CLUSTERED 
(
	[UserId] ASC,
	[Created] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[UserProperty]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[UserProperty](
	[UserId] [uniqueidentifier] NOT NULL,
	[Key] [varchar](100) NOT NULL,
	[Value] [varchar](max) NOT NULL,
 CONSTRAINT [PK_UserProperties] PRIMARY KEY CLUSTERED 
(
	[UserId] ASC,
	[Key] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
ALTER TABLE [dbo].[Authorization]  WITH CHECK ADD  CONSTRAINT [FK_Authorization_Domain] FOREIGN KEY([DomainId])
REFERENCES [dbo].[Domain] ([Id])
GO
ALTER TABLE [dbo].[Authorization] CHECK CONSTRAINT [FK_Authorization_Domain]
GO
ALTER TABLE [dbo].[Authorization]  WITH CHECK ADD  CONSTRAINT [FK_Authorization_Role] FOREIGN KEY([RoleId])
REFERENCES [dbo].[Role] ([Id])
GO
ALTER TABLE [dbo].[Authorization] CHECK CONSTRAINT [FK_Authorization_Role]
GO
ALTER TABLE [dbo].[Authorization]  WITH CHECK ADD  CONSTRAINT [FK_Authorization_User] FOREIGN KEY([UserId])
REFERENCES [dbo].[User] ([Id])
GO
ALTER TABLE [dbo].[Authorization] CHECK CONSTRAINT [FK_Authorization_User]
GO
ALTER TABLE [dbo].[ResourceRole]  WITH CHECK ADD  CONSTRAINT [FK_ResourceRole_Resource] FOREIGN KEY([ResourceId])
REFERENCES [dbo].[Resource] ([Id])
GO
ALTER TABLE [dbo].[ResourceRole] CHECK CONSTRAINT [FK_ResourceRole_Resource]
GO
ALTER TABLE [dbo].[ResourceRole]  WITH CHECK ADD  CONSTRAINT [FK_ResourceRole_Role] FOREIGN KEY([RoleId])
REFERENCES [dbo].[Role] ([Id])
GO
ALTER TABLE [dbo].[ResourceRole] CHECK CONSTRAINT [FK_ResourceRole_Role]
GO
ALTER TABLE [dbo].[ResourceType]  WITH CHECK ADD  CONSTRAINT [FK_ResourceType_Resource] FOREIGN KEY([ResourceId])
REFERENCES [dbo].[Resource] ([Id])
GO
ALTER TABLE [dbo].[ResourceType] CHECK CONSTRAINT [FK_ResourceType_Resource]
GO
ALTER TABLE [dbo].[Translation]  WITH CHECK ADD  CONSTRAINT [FK_Translation_Language] FOREIGN KEY([LanguageId])
REFERENCES [dbo].[Language] ([Id])
GO
ALTER TABLE [dbo].[Translation] CHECK CONSTRAINT [FK_Translation_Language]
GO
ALTER TABLE [dbo].[UserPassword]  WITH CHECK ADD  CONSTRAINT [FK_UserPassword_User] FOREIGN KEY([UserId])
REFERENCES [dbo].[User] ([Id])
GO
ALTER TABLE [dbo].[UserPassword] CHECK CONSTRAINT [FK_UserPassword_User]
GO
ALTER TABLE [dbo].[UserProperty]  WITH CHECK ADD  CONSTRAINT [FK_UserProperties_User] FOREIGN KEY([UserId])
REFERENCES [dbo].[User] ([Id])
GO
ALTER TABLE [dbo].[UserProperty] CHECK CONSTRAINT [FK_UserProperties_User]
GO
/****** Object:  StoredProcedure [dbo].[Zesty_CanAccess]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date,,>
-- Description:	<Description,,>
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_CanAccess]

	@path varchar(400),
	@userid uniqueidentifier

AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;

select * from [Authorization] a
join [user] u on u.Id = a.UserId
join [role] r on r.Id = a.RoleId
join [ResourceRole] rr on rr.RoleId = r.Id
join [Resource] rs on rs.Id = rr.ResourceId
join [Domain] d on a.DomainId = d.Id or a.DomainId = d.ParentDomainId
where 
rs.Url = @path
and u.Id = @userid

END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_ChangePassword]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date,,>
-- Description:	<Description,,>
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_ChangePassword]

	@userid uniqueidentifier,
	@previousPassword varchar(100),
	@newPassword varchar(100)

AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;

	
	IF EXISTS (SELECT * FROM [UserPassword] WHERE [UserId] = @userid AND [Password] = @previousPassword AND [Deleted] IS NULL) 
	BEGIN

		update [UserPassword] set Deleted = GETDATE() where [UserId] = @userid AND [Deleted] is null AND [Password] = @previousPassword;

		insert into [UserPassword] ([Id], [UserId], [Password], [Created]) VALUES (newid(), @userid, @newPassword, GETDATE());

		SELECT 'OK' as Status
	END
	ELSE
	BEGIN
		SELECT 'KO' as Status
	END






END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_ClientSetting_List]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date,,>
-- Description:	<Description,,>
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_ClientSetting_List]
AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;

	SELECT [Key], [Value]
	FROM [dbo].[ClientSetting]
	ORDER BY [Key]

END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_Domain_Add]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:      <Author, , Name>
-- Create Date: <Create Date, , >
-- Description: <Description, , >
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_Domain_Add]
(
	@id uniqueidentifier,
	@name varchar(200),
	@parent uniqueidentifier
)
AS
BEGIN
    -- SET NOCOUNT ON added to prevent extra result sets from
    -- interfering with SELECT statements.
    SET NOCOUNT ON



INSERT INTO [dbo].[Domain]
           ([Id]
           ,[ParentDomainId]
           ,[Name])
     VALUES
           (@id
           ,@parent
           ,@name);


END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_Domain_List]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date,,>
-- Description:	<Description,,>
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_Domain_List]
AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;

SELECT [Id]
      ,[ParentDomainId]
      ,[Name]
  FROM [dbo].[Domain]


END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_Domain_List_ByUsername]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date,,>
-- Description:	<Description,,>
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_Domain_List_ByUsername]

	@username varchar(100)

AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;

	
select d.[Id], d.[ParentDomainId], d.[Name] from 
[Authorization] a
join [Domain] d on d.Id = a.DomainId
join [User] u on u.Id = a.UserId
where 
u.Username = @username


END


GO
/****** Object:  StoredProcedure [dbo].[Zesty_History_Add]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date,,>
-- Description:	<Description,,>
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_History_Add]


			@userid as uniqueidentifier,
			@actor as varchar(100),
			@resource as varchar(200),
			@text as varchar(MAX)

AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;


INSERT INTO [dbo].[History]
           ([Id]
           ,[Created]
           ,[UserId]
           ,[Actor]
           ,[Resource]
           ,[Text])
     VALUES
           (newid()
           ,getdate()
           ,@userid
           ,@actor
           ,@resource
           ,@text)



END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_IsValid]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date,,>
-- Description:	<Description,,>
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_IsValid]

	@userid uniqueidentifier,
	@sessionid varchar(100),
	@token varchar(100)

AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;



	IF EXISTS (SELECT [UserId],[SessionId],[Value],[Created] FROM [dbo].[Token] WHERE [UserId] = @userid AND [SessionId] = @sessionid AND [Value] = @token AND [Deleted] IS NULL AND DATEDIFF(minute, Created, GETDATE()) <= 10) 
	BEGIN
		UPDATE [Token] SET [Deleted] = 1 WHERE [Value] = @token AND [IsReusable] = 0;

		SELECT 'Y' as IsValid
	END
	ELSE
	BEGIN
		SELECT 'N' as IsValid
	END




END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_Language_List]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date,,>
-- Description:	<Description,,>
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_Language_List]

AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;


SELECT [Id]
      ,[Name]
      ,[Description]
      ,[Direction]
  FROM [dbo].[Language]
ORDER BY [Id];

END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_Login]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date,,>
-- Description:	<Description,,>
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_Login]

	@username varchar(300),
	@password varchar(100)

AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;

	
select 
	u.Id,
	u.Username,
	u.Email,
	u.Firstname,
	u.Lastname,
	p.Created
from [user] u
join [UserPassword] p on u.Id = p.UserId
join [Authorization] a on a.UserId = u.Id
where 
[username] = @username
and p.Password = @password
and p.Deleted is null
and u.Deleted is null;



END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_RequireToken]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date,,>
-- Description:	<Description,,>
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_RequireToken]

	@path varchar(400)

AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;


	IF EXISTS (select * from [Resource] where [url] = @path and RequireToken = 1) 
	BEGIN
	   SELECT 'Y' as IsRequired
	END
	ELSE
	BEGIN
		SELECT 'N' as IsRequired
	END



END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_ResetPassword]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date,,>
-- Description:	<Description,,>
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_ResetPassword]

	@token uniqueidentifier,
	@password varchar(100)

AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;

	
	IF EXISTS (SELECT * FROM [User] WHERE [ResetToken] IS NOT NULL AND [ResetToken] = @token AND [Deleted] IS NULL) 
	BEGIN

		update [UserPassword] set Deleted = GETDATE() where [UserId] = (SELECT [Id] FROM [User] WHERE [ResetToken] = @token) AND [Deleted] is null;

		insert into [UserPassword] ([Id], [UserId], [Password], [Created]) VALUES (newid(), (SELECT [Id] FROM [User] WHERE [ResetToken] = @token), @password, GETDATE());

		update [User] set [ResetToken] = null where [ResetToken] = @token;
 
		SELECT 'OK' as Status
	END
	ELSE
	BEGIN
		SELECT 'KO' as Status
	END






END

GO
/****** Object:  StoredProcedure [dbo].[Zesty_Resource_IsPublic]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date,,>
-- Description:	<Description,,>
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_Resource_IsPublic]

	@path varchar(300)

AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;


	IF EXISTS (select * from [Resource] where [url] = @path and IsPublic = 1) 
	BEGIN
	   SELECT 'Y' as IsPublic
	END
	ELSE
	BEGIN
		SELECT 'N' as IsPublic
	END


	

END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_Resource_List_ByUsernameDomain]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date,,>
-- Description:	<Description,,>
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_Resource_List_ByUsernameDomain]

	@username varchar(200),
	@domainId uniqueidentifier
AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;


select 

	rs.Id,
	rs.ParentId,
	rs.IsPublic,
	rs.RequireToken,
	rs.[Url],
	rs.[Label],
	rs.[Title],
	rs.[Image]

from 
[user] u
join [Authorization] a on a.UserId = u.Id
join [Domain] d on d.Id = a.DomainId
join [Role] r on r.Id = a.RoleId
right join [ResourceRole] rr on rr.RoleId = r.Id
right join [Resource] rs on rs.Id = rr.ResourceId

where 
(u.Username = @username
and d.[Id] = @domainId)
OR rs.IsPublic = 1

order by rs.[Order]

END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_ResourceAuthorize]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:      <Author, , Name>
-- Create Date: <Create Date, , >
-- Description: <Description, , >
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_ResourceAuthorize]
(
    @resource uniqueidentifier,
    @role uniqueidentifier
)
AS
BEGIN
    -- SET NOCOUNT ON added to prevent extra result sets from
    -- interfering with SELECT statements.
    SET NOCOUNT ON


INSERT INTO [dbo].[ResourceRole]
           ([ResourceId]
           ,[RoleId])
     VALUES
           (@resource
           ,@role)


END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_ResourceDeauthorize]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:      <Author, , Name>
-- Create Date: <Create Date, , >
-- Description: <Description, , >
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_ResourceDeauthorize]
(
    @resource uniqueidentifier,
    @role uniqueidentifier
)
AS
BEGIN
    -- SET NOCOUNT ON added to prevent extra result sets from
    -- interfering with SELECT statements.
    SET NOCOUNT ON


DELETE FROM [dbo].[ResourceRole]
           WHERE [ResourceId] = @resource
           AND [RoleId] = @role


END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_ResourceList]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:      <Author, , Name>
-- Create Date: <Create Date, , >
-- Description: <Description, , >
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_ResourceList]


AS
BEGIN
    -- SET NOCOUNT ON added to prevent extra result sets from
    -- interfering with SELECT statements.
    SET NOCOUNT ON



SELECT [Id]
      ,[ParentId]
      ,[IsPublic]
      ,[RequireToken]
      ,[Order]
      ,[Url]
      ,[Label]
      ,[Image]
      ,[Title]
  FROM [dbo].[Resource];




END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_ResourceListGrant]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:      <Author, , Name>
-- Create Date: <Create Date, , >
-- Description: <Description, , >
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_ResourceListGrant]
(
    @role uniqueidentifier
)
AS
BEGIN
    -- SET NOCOUNT ON added to prevent extra result sets from
    -- interfering with SELECT statements.
    SET NOCOUNT ON



SELECT r.[Id]

  FROM [dbo].[Resource] r
LEFT JOIN [dbo].[ResourceRole] rr on r.Id = rr.ResourceId
LEFT JOIN [dbo].[Role] l on l.Id = rr.RoleId
WHERE l.Id = @role



END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_ResourceType_List_ByResourceName]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date,,>
-- Description:	<Description,,>
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_ResourceType_List_ByResourceName]
	
	@resourceName varchar(300)
AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;

	
SELECT 
	rt.[Type]
FROM 
	[dbo].[Resource] r
	join [dbo].[ResourceType] rt on rt.ResourceId = r.Id
WHERE
	r.Url = @resourceName

  

END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_Role_Add]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:      <Author, , Name>
-- Create Date: <Create Date, , >
-- Description: <Description, , >
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_Role_Add]
(
	@id uniqueidentifier,
	@name varchar(200)
)
AS
BEGIN
    -- SET NOCOUNT ON added to prevent extra result sets from
    -- interfering with SELECT statements.
    SET NOCOUNT ON



INSERT INTO [dbo].[Role]
           ([Id]
           ,[Name])
     VALUES
           (@id
           ,@name);


END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_Role_List]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date,,>
-- Description:	<Description,,>
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_Role_List]


AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;


select r.[Id], r.[Name] from 
[Role] r

END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_Role_List_ByUsernameDomain]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date,,>
-- Description:	<Description,,>
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_Role_List_ByUsernameDomain]

	@username varchar(100),
	@domain uniqueidentifier

AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;


select r.[Id], r.[Name] from 
[Authorization] a
join [Domain] d on d.Id = a.DomainId
join [Role] r on r.Id = a.RoleId
join [User] u on u.Id = a.UserId
where 
u.Username = @username
and d.[Id] = @domain


END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_ServerSetting_List]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date,,>
-- Description:	<Description,,>
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_ServerSetting_List]

AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;


SELECT [Key]
	  ,[Order]
      ,[Value]
  FROM [dbo].[ServerSetting]
  ORDER BY [Order]

END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_Token_Add]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date,,>
-- Description:	<Description,,>
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_Token_Add]

	@userid uniqueidentifier,
	@sessionid varchar(100),
	@value varchar(100),
	@reusable bit

AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;


INSERT INTO [dbo].[Token]
           ([UserId]
           ,[SessionId]
           ,[Value]
		   ,[IsReusable]
           ,[Created])
     VALUES
           (@userid
           ,@sessionid
           ,@value
		   ,@reusable
           ,getdate());


END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_Translation_List_ByLanguage]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date,,>
-- Description:	<Description,,>
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_Translation_List_ByLanguage]

	@language varchar(50)

AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;



SELECT 
	t.[Id]
	,t.[LanguageId]
	,t.[Original]
	,t.[Translated]
FROM 
	[dbo].[Translation] t
	join [dbo].[Language] l on l.Id = t.LanguageId
WHERE 
l.[Name] = @language


END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_User_Add]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date,,>
-- Description:	<Description,,>
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_User_Add]

	@username varchar(200),
	@email varchar(200),
	@firstname varchar(50),
	@lastname varchar(50)

AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;


INSERT INTO [dbo].[User] ([Id],[Username],[Email],[Firstname],[Lastname],[ResetToken],[Deleted],[Created]) VALUES (newid(),@username,@email,@firstname,@lastname,null,null,getdate());



END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_User_AlreadyExists]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:      <Author, , Name>
-- Create Date: <Create Date, , >
-- Description: <Description, , >
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_User_AlreadyExists]
(
	@username varchar(200),
	@email varchar(200)
)
AS
BEGIN
    -- SET NOCOUNT ON added to prevent extra result sets from
    -- interfering with SELECT statements.
    SET NOCOUNT ON

	SELECT * FROM [User] WHERE [Username] = @username OR [Email] = @email;

END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_User_Authorize]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:      <Author, , Name>
-- Create Date: <Create Date, , >
-- Description: <Description, , >
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_User_Authorize]
(
	@user varchar(200),
	@role uniqueidentifier,
	@domain uniqueidentifier
)
AS
BEGIN
    -- SET NOCOUNT ON added to prevent extra result sets from
    -- interfering with SELECT statements.
    SET NOCOUNT ON


	
if TRY_CONVERT(UNIQUEIDENTIFIER, @user) is not null
	INSERT INTO [dbo].[Authorization]
           ([UserId]
           ,[DomainId]
           ,[RoleId])
     VALUES
           (@user
           ,@domain
           ,@role);
else
	INSERT INTO [dbo].[Authorization]
           ([UserId]
           ,[DomainId]
           ,[RoleId])
     VALUES
           ((select [id] from [user] where [username] = @user)
           ,@domain
           ,@role);


	
END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_User_Deauthorize]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:      <Author, , Name>
-- Create Date: <Create Date, , >
-- Description: <Description, , >
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_User_Deauthorize]
(
	@user varchar(200),
	@role uniqueidentifier,
	@domain uniqueidentifier
)
AS
BEGIN
    -- SET NOCOUNT ON added to prevent extra result sets from
    -- interfering with SELECT statements.
    SET NOCOUNT ON


	
if TRY_CONVERT(UNIQUEIDENTIFIER, @user) is not null
	DELETE FROM [dbo].[Authorization] 
	WHERE
		[UserId] = @user 
		AND [DomainId] = @domain
        AND [RoleId] = @role;

else
	DELETE FROM [dbo].[Authorization] 
	WHERE
		[UserId] = (select [id] from [user] where [username] = @user) 
		AND [DomainId] = @domain
        AND [RoleId] = @role;
	
END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_User_Delete]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:      <Author, , Name>
-- Create Date: <Create Date, , >
-- Description: <Description, , >
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_User_Delete]
(
	@userid uniqueidentifier
)
AS
BEGIN
    -- SET NOCOUNT ON added to prevent extra result sets from
    -- interfering with SELECT statements.
    SET NOCOUNT ON

	update [user] set [Deleted] = getdate() where [Id] = @userid;


END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_User_Get]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:      <Author, , Name>
-- Create Date: <Create Date, , >
-- Description: <Description, , >
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_User_Get]
(
	@user varchar(200)
)
AS
BEGIN
    -- SET NOCOUNT ON added to prevent extra result sets from
    -- interfering with SELECT statements.
    SET NOCOUNT ON


	
if TRY_CONVERT(UNIQUEIDENTIFIER, @user) is not null
	select [Id], [Username], [Email], [Firstname], [Lastname], [Deleted], [Created] from [user] where [id] = @user;

else
	select [Id], [Username], [Email], [Firstname], [Lastname], [Deleted], [Created] from [user] where [username] = @user or [email] = @user;

	
END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_User_Get_ByResetToken]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date,,>
-- Description:	<Description,,>
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_User_Get_ByResetToken]

	@token uniqueidentifier

AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;

	
select 
	u.Id,
	u.Username,
	u.Email,
	u.Firstname,
	u.Lastname
from [user] u
where 
u.ResetToken = @token
and u.ResetToken is not null
and u.Deleted is null;



END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_User_Get_ByUsername]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date,,>
-- Description:	<Description,,>
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_User_Get_ByUsername]

	@username varchar(200)

AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;

	
select 
	u.Id,
	u.Username,
	u.Email,
	u.Firstname,
	u.Lastname
from [user] u
where 
[username] = @username


END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_User_HardDelete]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:      <Author, , Name>
-- Create Date: <Create Date, , >
-- Description: <Description, , >
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_User_HardDelete]
(
	@userid uniqueidentifier
)
AS
BEGIN
    -- SET NOCOUNT ON added to prevent extra result sets from
    -- interfering with SELECT statements.
    SET NOCOUNT ON

	delete from [dbo].[Authorization] where [userid] = @userid;
	delete from [dbo].[Token] where [userid] = @userid;
	delete from [dbo].[UserPassword] where [userid] = @userid;
	delete from [dbo].[UserProperty]  where [userid] = @userid;
	delete from [dbo].[User] where [id] = @userid;
END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_User_List]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:      <Author, , Name>
-- Create Date: <Create Date, , >
-- Description: <Description, , >
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_User_List]


AS
BEGIN
    -- SET NOCOUNT ON added to prevent extra result sets from
    -- interfering with SELECT statements.
    SET NOCOUNT ON

	select [Id], [Username], [Email], [Firstname], [Lastname], [Deleted], [Created] from [user]
END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_User_Update]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date,,>
-- Description:	<Description,,>
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_User_Update]

	@userid uniqueidentifier,
	@username varchar(200),
	@email varchar(200),
	@firstname varchar(50),
	@lastname varchar(50)

AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;


UPDATE [User] SET
	[Username] = @username,
	[Email] = @email,
	[Firstname] = @firstname,
	[Lastname] = @lastname
WHERE
	[Id] = @userid;


END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_User_Update_ResetToken]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date,,>
-- Description:	<Description,,>
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_User_Update_ResetToken]

	@email varchar(300)

AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;

	declare @token as uniqueidentifier;

	set @token = newid();


	update [user] set ResetToken = @token WHERE [Deleted] is null and [Email] = @email;

	select @token;
END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_UserProperty_Delete]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date,,>
-- Description:	<Description,,>
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_UserProperty_Delete]

	@userid uniqueidentifier,
	@propertyName varchar(100),
	@propertyValue varchar(max)

AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;


	DELETE FROM [UserProperty] WHERE [UserId] = @userid AND [Key] = @propertyName;

END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_UserProperty_List_ByUserid]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date,,>
-- Description:	<Description,,>
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_UserProperty_List_ByUserid]

	@userid uniqueidentifier

AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;

SELECT [Key],[Value]
FROM [dbo].[UserProperty]
WHERE
[UserId] = @userid



END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_UserProperty_Set]    Script Date: 1/5/2021 4:53:40 PM ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date,,>
-- Description:	<Description,,>
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_UserProperty_Set]

	@userid uniqueidentifier,
	@propertyName varchar(100),
	@propertyValue varchar(max)

AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;



	IF EXISTS (SELECT * FROM [UserProperty] WHERE [UserId] = @userid AND [Key] = @propertyName) 
	BEGIN
		UPDATE [UserProperty] 
		SET [Value] = @propertyValue
		WHERE [UserId] = @userid AND [Key] = @propertyName;
	END
	ELSE
	BEGIN

		INSERT INTO [dbo].[UserProperty]
				   ([UserId]
				   ,[Key]
				   ,[Value])
			 VALUES
				   (@userid
				   ,@propertyName
				   ,@propertyValue);

	END


END
GO




CREATE TABLE [dbo].[Trace] (
    [Created]   DATETIME      NOT NULL,
    [Class]     VARCHAR (200) NOT NULL,
    [Method]    VARCHAR (100) NOT NULL,
    [Hostname]  VARCHAR (200) NULL,
    [ClientIP]  VARCHAR (50)  NULL,
    [SessionID] VARCHAR (100) NULL,
    [Username]  VARCHAR (100) NULL,
    [Domain]    VARCHAR (100) NULL,
    [Resource]  VARCHAR (200) NULL,
    [Message]   VARCHAR (300) NULL,
    [Error]     VARCHAR (500) NULL,
    [Millis]    INT           NOT NULL
);
GO




-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date,,>
-- Description:	<Description,,>
-- =============================================
CREATE PROCEDURE [dbo].[DeviceDetail]

	@domain uniqueidentifier,
	@device uniqueidentifier

AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;




	select 
		d.*
		,dm.[Name] as Model
		,dm.[Properties] as Properties
		,db.[Name] as Brand
		,dt.[Id] as DeviceTypeId
		,dt.[Name] as DeviceTypeName
		,dt.[Icon] as DeviceTypeIcon
		,dt.[MapPin] as DeviceTypeMapPin
		,dt.[Color] as DeviceTypeColor
		,dp.[Key] as Property
		,dp.[Value] as PropertyValue
	from Device d
	join DeviceModel dm on dm.Id = d.DeviceModelId
	join DeviceBrand db on db.Id = dm.DeviceBrandId
	join DeviceType dt on dt.Id = dm.DeviceTypeId
	left join DeviceProperty dp on dp.DeviceId = d.Id
	where
	d.DomainId = @domain
	and d.Id = @device
	and d.deleted is null
	




END
GO

