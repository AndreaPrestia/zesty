/****** Object:  Table [dbo].[Authorization]    Script Date: 22/04/2021 21:09:58 ******/
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
)WITH (STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Bearer]    Script Date: 22/04/2021 21:09:58 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Bearer](
	[Id] [varchar](200) NOT NULL,
	[UserId] [uniqueidentifier] NOT NULL,
	[Created] [datetime] NOT NULL,
	[Deleted] [datetime] NULL,
 CONSTRAINT [PK_Bearer] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[ClientSetting]    Script Date: 22/04/2021 21:09:58 ******/
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
)WITH (STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Domain]    Script Date: 22/04/2021 21:09:58 ******/
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
)WITH (STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[History]    Script Date: 22/04/2021 21:09:58 ******/
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
)WITH (STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Language]    Script Date: 22/04/2021 21:09:58 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Language](
	[Id] [int] IDENTITY(1,1) NOT NULL,
	[Name] [varchar](50) NOT NULL,
	[Description] [varchar](100) NOT NULL,
	[Direction] [char](1) NOT NULL,
 CONSTRAINT [PK_Language] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Resource]    Script Date: 22/04/2021 21:09:58 ******/
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
)WITH (STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[ResourceDomain]    Script Date: 22/04/2021 21:09:58 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[ResourceDomain](
	[ResourceId] [uniqueidentifier] NOT NULL,
	[DomainId] [uniqueidentifier] NOT NULL,
 CONSTRAINT [PK_ResourceDomain] PRIMARY KEY CLUSTERED 
(
	[ResourceId] ASC,
	[DomainId] ASC
)WITH (STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[ResourceRole]    Script Date: 22/04/2021 21:09:58 ******/
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
)WITH (STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[ResourceType]    Script Date: 22/04/2021 21:09:58 ******/
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
)WITH (STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Role]    Script Date: 22/04/2021 21:09:58 ******/
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
)WITH (STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[ServerSetting]    Script Date: 22/04/2021 21:09:58 ******/
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
)WITH (STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Session]    Script Date: 22/04/2021 21:09:58 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Session](
	[Id] [varchar](100) NOT NULL,
	[Bearer] [varchar](300) NOT NULL,
	[UserId] [uniqueidentifier] NOT NULL,
	[Created] [datetime] NOT NULL,
	[Deleted] [datetime] NULL,
	[Body] [varchar](max) NOT NULL,
 CONSTRAINT [PK_Session] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Token]    Script Date: 22/04/2021 21:09:58 ******/
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
/****** Object:  Table [dbo].[Trace]    Script Date: 22/04/2021 21:09:58 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Trace](
	[Created] [datetime] NOT NULL,
	[Class] [varchar](200) NOT NULL,
	[Method] [varchar](100) NOT NULL,
	[Hostname] [varchar](200) NULL,
	[ClientIP] [varchar](50) NULL,
	[SessionID] [varchar](100) NULL,
	[Username] [varchar](100) NULL,
	[Domain] [varchar](100) NULL,
	[Resource] [varchar](200) NULL,
	[Message] [varchar](300) NULL,
	[Error] [varchar](500) NULL,
	[Millis] [int] NOT NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Translation]    Script Date: 22/04/2021 21:09:58 ******/
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
)WITH (STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[User]    Script Date: 22/04/2021 21:09:58 ******/
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
	[ResetTokenCreated] [datetime] NULL,
	[Deleted] [datetime] NULL,
	[Created] [datetime] NOT NULL,
	[DomainId] [uniqueidentifier] NULL,
 CONSTRAINT [PK_User] PRIMARY KEY CLUSTERED 
(
	[Id] ASC
)WITH (STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[UserPassword]    Script Date: 22/04/2021 21:09:58 ******/
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
)WITH (STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[UserProperty]    Script Date: 22/04/2021 21:09:58 ******/
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
)WITH (STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
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
ALTER TABLE [dbo].[Bearer]  WITH CHECK ADD  CONSTRAINT [FK_Bearer_User] FOREIGN KEY([UserId])
REFERENCES [dbo].[User] ([Id])
GO
ALTER TABLE [dbo].[Bearer] CHECK CONSTRAINT [FK_Bearer_User]
GO
ALTER TABLE [dbo].[ResourceDomain]  WITH CHECK ADD  CONSTRAINT [FK_ResourceDomain_Domain] FOREIGN KEY([DomainId])
REFERENCES [dbo].[Domain] ([Id])
GO
ALTER TABLE [dbo].[ResourceDomain] CHECK CONSTRAINT [FK_ResourceDomain_Domain]
GO
ALTER TABLE [dbo].[ResourceDomain]  WITH CHECK ADD  CONSTRAINT [FK_ResourceDomain_Resource] FOREIGN KEY([ResourceId])
REFERENCES [dbo].[Resource] ([Id])
GO
ALTER TABLE [dbo].[ResourceDomain] CHECK CONSTRAINT [FK_ResourceDomain_Resource]
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
/****** Object:  StoredProcedure [dbo].[Zesty_Bearer_Add]    Script Date: 22/04/2021 21:09:58 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date,,>
-- Description:	<Description,,>
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_Bearer_Add]
(
	@bearer varchar(200),
	@userid uniqueidentifier
)
AS
BEGIN
    -- SET NOCOUNT ON added to prevent extra result sets from
    -- interfering with SELECT statements.
    SET NOCOUNT ON

INSERT INTO [dbo].[Bearer]
           ([Id]
           ,[UserId]
           ,[Created]
           ,[Deleted])
     VALUES
           (@bearer
           ,@userid
           ,getdate()
           ,null)
END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_Bearer_GetSecret]    Script Date: 22/04/2021 21:09:58 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date,,>
-- Description:	<Description,,>
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_Bearer_GetSecret]
(
    @bearer varchar(200)
)
AS
BEGIN
    -- SET NOCOUNT ON added to prevent extra result sets from
    -- interfering with SELECT statements.
    SET NOCOUNT ON

  SELECT p.[Password]
  FROM [dbo].[Bearer] b
  JOIN [User] u ON u.Id = b.UserId
  JOIN [UserPassword] p ON p.UserId = u.Id
  WHERE 
  b.Id = @bearer
  and b.Deleted is null
  and u.Deleted is null
  and p.Deleted is null

END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_CanAccess]    Script Date: 22/04/2021 21:09:58 ******/
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
	@userid uniqueidentifier,
	@domainid uniqueidentifier

AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;

IF @domainid is not null
select * from [dbo].[Authorization] a
join [dbo].[user] u on u.Id = a.UserId
join [dbo].[role] r on r.Id = a.RoleId
join [dbo].[ResourceRole] rr on rr.RoleId = r.Id
join [dbo].[Resource] rs on rs.Id = rr.ResourceId
join [dbo].[ResourceDomain] rd on rd.ResourceId = rs.Id
join [dbo].[Domain] d on a.DomainId = d.Id or a.DomainId = d.ParentDomainId
where 
rs.[Url] = @path
and u.Id = @userid
and d.Id = @domainid
else
select * from [dbo].[Authorization] a
join [dbo].[user] u on u.Id = a.UserId
join [dbo].[role] r on r.Id = a.RoleId
join [dbo].[ResourceRole] rr on rr.RoleId = r.Id
join [dbo].[Resource] rs on rs.Id = rr.ResourceId
join [dbo].[Domain] d on a.DomainId = d.Id or a.DomainId = d.ParentDomainId
where 
rs.[Url] = @path
and u.Id = @userid

END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_ChangePassword]    Script Date: 22/04/2021 21:09:58 ******/
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

	
	IF EXISTS (SELECT * FROM [dbo].[UserPassword] WHERE [UserId] = @userid AND [Password] = @previousPassword AND [Deleted] IS NULL) 
	BEGIN

		update [dbo].[UserPassword] set Deleted = GETDATE() where [UserId] = @userid AND [Deleted] is null AND [Password] = @previousPassword;

		insert into [dbo].[UserPassword] ([Id], [UserId], [Password], [Created]) VALUES (newid(), @userid, @newPassword, GETDATE());

		SELECT 'OK' as Status
	END
	ELSE
	BEGIN
		SELECT 'KO' as Status
	END






END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_ClientSetting_Delete]    Script Date: 22/04/2021 21:09:58 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:      <Author, , Name>
-- Create Date: <Create Date, , >
-- Description: <Description, , >
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_ClientSetting_Delete]
(
    -- Add the parameters for the stored procedure here
    @key varchar(100)
)
AS
BEGIN
    -- SET NOCOUNT ON added to prevent extra result sets from
    -- interfering with SELECT statements.
    SET NOCOUNT ON

	DELETE FROM [dbo].[ClientSetting] WHERE [Key] = @key
END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_ClientSetting_List]    Script Date: 22/04/2021 21:09:58 ******/
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
/****** Object:  StoredProcedure [dbo].[Zesty_ClientSetting_Set]    Script Date: 22/04/2021 21:09:58 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:      <Author, , Name>
-- Create Date: <Create Date, , >
-- Description: <Description, , >
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_ClientSetting_Set]
(
    -- Add the parameters for the stored procedure here
    @key varchar(100),
	@value varchar(300)
)
AS
BEGIN
    -- SET NOCOUNT ON added to prevent extra result sets from
    -- interfering with SELECT statements.
    SET NOCOUNT ON

   IF EXISTS (SELECT * FROM [dbo].[ClientSetting] WHERE [Key] = @key) 
	BEGIN
		UPDATE [dbo].[ClientSetting] 
		SET [Value] = @value
		WHERE [Key] = @key;
	END
	ELSE
	BEGIN

		INSERT INTO [dbo].[ClientSetting]
				   ([Key]
				   ,[Value])
			 VALUES
				   (@key
				   ,@value);

	END
END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_Domain_Add]    Script Date: 22/04/2021 21:09:58 ******/
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
/****** Object:  StoredProcedure [dbo].[Zesty_Domain_List]    Script Date: 22/04/2021 21:09:58 ******/
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
/****** Object:  StoredProcedure [dbo].[Zesty_Domain_List_ByUsername]    Script Date: 22/04/2021 21:09:58 ******/
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
/****** Object:  StoredProcedure [dbo].[Zesty_DomainProperty_Delete]    Script Date: 22/04/2021 21:09:58 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date,,>
-- Description:	<Description,,>
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_DomainProperty_Delete]

	@domainId uniqueidentifier,
	@propertyName varchar(100)

AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;


	DELETE FROM [dbo].[DomainProperty] WHERE [DomainId] = @domainId AND [Key] = @propertyName;

END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_DomainProperty_Get]    Script Date: 22/04/2021 21:09:58 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date,,>
-- Description:	<Description,,>
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_DomainProperty_Get]

	@domainId uniqueidentifier,
	@propertyName varchar(100)

AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;

SELECT [Value]
FROM [dbo].[DomainProperty]
WHERE
[DomainId] = @domainId AND [Key] = @propertyName



END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_DomainProperty_List]    Script Date: 22/04/2021 21:09:58 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date,,>
-- Description:	<Description,,>
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_DomainProperty_List]

	@domainId uniqueidentifier

AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;

SELECT [Key],[Value]
FROM [dbo].[DomainProperty]
WHERE
[DomainId] = @domainId



END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_DomainProperty_Set]    Script Date: 22/04/2021 21:09:58 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		<Author,,Name>
-- Create date: <Create Date,,>
-- Description:	<Description,,>
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_DomainProperty_Set]

	@domainId uniqueidentifier,
	@propertyName varchar(100),
	@propertyValue varchar(max)

AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;



	IF EXISTS (SELECT * FROM [dbo].[DomainProperty] WHERE [DomainId] = @domainId AND [Key] = @propertyName) 
	BEGIN
		UPDATE [dbo].[DomainProperty] 
		SET [Value] = @propertyValue
		WHERE [DomainId] = @domainId AND [Key] = @propertyName;
	END
	ELSE
	BEGIN

		INSERT INTO [dbo].[DomainProperty]
				   ([DomainId]
				   ,[Key]
				   ,[Value])
			 VALUES
				   (@domainId
				   ,@propertyName
				   ,@propertyValue);

	END


END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_History_Add]    Script Date: 22/04/2021 21:09:58 ******/
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
/****** Object:  StoredProcedure [dbo].[Zesty_IsValid]    Script Date: 22/04/2021 21:09:58 ******/
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
		UPDATE [dbo].[Token] SET [Deleted] = 1 WHERE [Value] = @token AND [IsReusable] = 0;

		SELECT 'Y' as IsValid
	END
	ELSE
	BEGIN
		SELECT 'N' as IsValid
	END




END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_Language_List]    Script Date: 22/04/2021 21:09:58 ******/
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
/****** Object:  StoredProcedure [dbo].[Zesty_Login]    Script Date: 22/04/2021 21:09:58 ******/
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
/****** Object:  StoredProcedure [dbo].[Zesty_RequireToken]    Script Date: 22/04/2021 21:09:58 ******/
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


	IF EXISTS (select * from [dbo].[Resource] where [url] = @path and RequireToken = 1) 
	BEGIN
	   SELECT 'Y' as IsRequired
	END
	ELSE
	BEGIN
		SELECT 'N' as IsRequired
	END



END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_ResetPassword]    Script Date: 22/04/2021 21:09:58 ******/
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

	
	IF EXISTS (SELECT * FROM [dbo].[User] WHERE [ResetToken] IS NOT NULL AND [ResetToken] = @token AND [Deleted] IS NULL) 
	BEGIN

		update [dbo].[UserPassword] set Deleted = GETDATE() where [UserId] = (SELECT [Id] FROM [dbo].[User] WHERE [ResetToken] = @token) AND [Deleted] is null;

		insert into [dbo].[UserPassword] ([Id], [UserId], [Password], [Created]) VALUES (newid(), (SELECT [Id] FROM [dbo].[User] WHERE [ResetToken] = @token), @password, GETDATE());

		update [dbo].[User] set [ResetToken] = null where [ResetToken] = @token;
 
		SELECT 'OK' as Status
	END
	ELSE
	BEGIN
		SELECT 'KO' as Status
	END






END

GO
/****** Object:  StoredProcedure [dbo].[Zesty_Resource_Add]    Script Date: 22/04/2021 21:09:58 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:      <Author, , Name>
-- Create Date: <Create Date, , >
-- Description: <Description, , >
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_Resource_Add]	
	@parentId uniqueidentifier,
	@isPublic bit,
	@requireToken bit,
	@order int,
	@url varchar(400),
	@label varchar(50),
	@image varchar(300),
	@title varchar(100),
	@type varchar(500),
	@domain uniqueidentifier
AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;
	BEGIN TRANSACTION; 
	BEGIN TRY
	declare @resourceId as uniqueidentifier;

	set @resourceId = NEWID();

	INSERT INTO [dbo].[Resource]
           ([Id]
           ,[ParentId]
           ,[IsPublic]
           ,[RequireToken]
           ,[Order]
           ,[Url]
           ,[Label]
           ,[Image]
           ,[Title])
     VALUES
           (@resourceId
           ,@parentId
           ,@isPublic
           ,@requireToken
           ,@order
           ,@url
           ,@label
           ,@image
           ,@title)
	
	IF @isPublic = 0
     INSERT INTO [dbo].[ResourceDomain]
           ([ResourceId]
           ,[DomainId])
      VALUES
           (@resourceId
           ,@domain)

	IF @type IS NOT NULL
	BEGIN
	INSERT INTO [dbo].[ResourceType]
           ([ResourceId]
           ,[Type])
     VALUES
           (@resourceId
           ,@type)
	END

	END TRY
	BEGIN CATCH  
			SELECT   
			ERROR_NUMBER() AS ErrorNumber  
			,ERROR_SEVERITY() AS ErrorSeverity  
			,ERROR_STATE() AS ErrorState  
			,ERROR_PROCEDURE() AS ErrorProcedure  
			,ERROR_LINE() AS ErrorLine  
			,ERROR_MESSAGE() AS ErrorMessage;  

		IF @@TRANCOUNT > 0  
			ROLLBACK TRANSACTION;  
		THROW;
	END CATCH;

IF @@TRANCOUNT > 0  
		COMMIT TRANSACTION;  
END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_Resource_Delete]    Script Date: 22/04/2021 21:09:58 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:      <Author, , Name>
-- Create Date: <Create Date, , >
-- Description: <Description, , >
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_Resource_Delete]
    @resourceId uniqueidentifier
AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;
	BEGIN TRANSACTION; 
	BEGIN TRY

	DELETE FROM [dbo].[ResourceType] WHERE [ResourceId] = @resourceId;
	DELETE FROM [dbo].[ResourceRole] WHERE [ResourceId] = @resourceId;
	DELETE FROM [dbo].[ResourceDomain] WHERE [ResourceId] = @resourceId;
	DELETE FROM [dbo].[Resource] WHERE [Id] = @resourceId;

	END TRY
	BEGIN CATCH  
			SELECT   
			ERROR_NUMBER() AS ErrorNumber  
			,ERROR_SEVERITY() AS ErrorSeverity  
			,ERROR_STATE() AS ErrorState  
			,ERROR_PROCEDURE() AS ErrorProcedure  
			,ERROR_LINE() AS ErrorLine  
			,ERROR_MESSAGE() AS ErrorMessage;  

		IF @@TRANCOUNT > 0  
			ROLLBACK TRANSACTION;  
		THROW;
	END CATCH;

IF @@TRANCOUNT > 0  
		COMMIT TRANSACTION;  
END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_Resource_IsPublic]    Script Date: 22/04/2021 21:09:58 ******/
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


	IF EXISTS (select * from [dbo].[Resource] where [url] = @path and IsPublic = 1) 
	BEGIN
	   SELECT 'Y' as IsPublic
	END
	ELSE
	BEGIN
		SELECT 'N' as IsPublic
	END


	

END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_Resource_List]    Script Date: 22/04/2021 21:09:58 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:      <Author, , Name>
-- Create Date: <Create Date, , >
-- Description: <Description, , >
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_Resource_List]
AS
BEGIN
    -- SET NOCOUNT ON added to prevent extra result sets from
    -- interfering with SELECT statements.
    SET NOCOUNT ON


  SELECT 
       rs.[Id]
      ,rs.[ParentId]
      ,rs.[IsPublic]
      ,rs.[RequireToken]
      ,rs.[Order]
      ,rs.[Url]
      ,rs.[Label]
      ,rs.[Image]
      ,rs.[Title]
	  ,rt.[Type]
	  ,d.Id as DomainId
	  ,d.[Name] as Domain
  FROM [dbo].[Resource] rs
  JOIN [dbo].[ResourceDomain] rd
  ON rd.ResourceId = rs.Id
  JOIN [dbo].[Domain] d 
  ON d.Id = rd.DomainId
  LEFT JOIN [dbo].[ResourceType] rt
  ON rt.ResourceId = rs.[Id]
  ORDER BY [Url] ASC

END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_Resource_List_ByUsernameDomain]    Script Date: 22/04/2021 21:09:58 ******/
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
[dbo].[user] u
join [dbo].[Authorization] a on a.UserId = u.Id
join [dbo].[Domain] d on d.Id = a.DomainId
join [dbo].[Role] r on r.Id = a.RoleId
join [dbo].[ResourceDomain] rd on rd.DomainId = d.[Id]
right join [ResourceRole] rr on rr.RoleId = r.Id
right join [Resource] rs on rs.Id = rr.ResourceId

where 
(u.Username = @username
and d.[Id] = @domainId)
OR rs.IsPublic = 1

order by rs.[Order]

END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_Resource_Update]    Script Date: 22/04/2021 21:09:58 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:      <Author, , Name>
-- Create Date: <Create Date, , >
-- Description: <Description, , >
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_Resource_Update]
    @resourceId uniqueidentifier,
	@parentId uniqueidentifier,
	@isPublic bit,
	@requireToken bit,
	@order int,
	@url varchar(400),
	@label varchar(50),
	@image varchar(300),
	@title varchar(100),
	@type varchar(500),
	@domain uniqueidentifier
AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;
	BEGIN TRANSACTION; 
	BEGIN TRY

	UPDATE [dbo].[Resource]
   SET 
       [ParentId] = @parentId
      ,[IsPublic] = @isPublic
      ,[RequireToken] = @requireToken
      ,[Order] = @order
      ,[Url] = @url
      ,[Label] = @label
      ,[Image] = @image
      ,[Title] = @title
   WHERE [Id] = @resourceId
	
	IF @isPublic = 0
	IF NOT EXISTS(SELECT 1 FROM [dbo].[ResourceDomain] WHERE [ResourceId] = @resourceId AND [DomainId] = @domain)
	    INSERT INTO [dbo].[ResourceDomain] ([ResourceId], [DomainId]) VALUES (@resourceId, @domain)

	IF @type IS NOT NULL
	BEGIN
    IF EXISTS (SELECT 1 FROM [dbo].[ResourceType] WHERE [ResourceId] = @resourceId)
	BEGIN
	UPDATE [dbo].[ResourceType] SET [Type] = @type WHERE [ResourceId] = @resourceId
	END
	ELSE
	BEGIN
	INSERT INTO [dbo].[ResourceType]
           ([ResourceId]
           ,[Type])
     VALUES
           (@resourceId
           ,@type)
	END
	END

	END TRY
	BEGIN CATCH  
			SELECT   
			ERROR_NUMBER() AS ErrorNumber  
			,ERROR_SEVERITY() AS ErrorSeverity  
			,ERROR_STATE() AS ErrorState  
			,ERROR_PROCEDURE() AS ErrorProcedure  
			,ERROR_LINE() AS ErrorLine  
			,ERROR_MESSAGE() AS ErrorMessage;  

		IF @@TRANCOUNT > 0  
			ROLLBACK TRANSACTION;  
		THROW;
	END CATCH;

IF @@TRANCOUNT > 0  
		COMMIT TRANSACTION;  
END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_ResourceAuthorize]    Script Date: 22/04/2021 21:09:58 ******/
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
/****** Object:  StoredProcedure [dbo].[Zesty_ResourceDeauthorize]    Script Date: 22/04/2021 21:09:58 ******/
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
/****** Object:  StoredProcedure [dbo].[Zesty_ResourceList]    Script Date: 22/04/2021 21:09:58 ******/
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
  FROM [dbo].[Resource]
  ORDER BY [Order];



END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_ResourceListGrant]    Script Date: 22/04/2021 21:09:58 ******/
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
/****** Object:  StoredProcedure [dbo].[Zesty_ResourceListGrantDomain]    Script Date: 22/04/2021 21:09:58 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:      <Author, , Name>
-- Create Date: <Create Date, , >
-- Description: <Description, , >
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_ResourceListGrantDomain]
(
    @role uniqueidentifier,
	@domain uniqueidentifier
)
AS
BEGIN
    -- SET NOCOUNT ON added to prevent extra result sets from
    -- interfering with SELECT statements.
    SET NOCOUNT ON



SELECT r.[Id]

  FROM [dbo].[Resource] r
  JOIN [dbo].[ResourceDomain] rd on rd.ResourceId = r.[Id]
LEFT JOIN [dbo].[ResourceRole] rr on r.Id = rr.ResourceId
LEFT JOIN [dbo].[Role] l on l.Id = rr.RoleId
WHERE l.Id = @role AND rd.DomainId = @domain



END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_ResourceType_List_ByResourceName]    Script Date: 22/04/2021 21:09:58 ******/
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
	r.[Url] = @resourceName

  

END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_Role_Add]    Script Date: 22/04/2021 21:09:58 ******/
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
/****** Object:  StoredProcedure [dbo].[Zesty_Role_List]    Script Date: 22/04/2021 21:09:58 ******/
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


select r.[Id], r.[Name] from [dbo].[Role] r

END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_Role_List_ByUsernameDomain]    Script Date: 22/04/2021 21:09:58 ******/
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
join [ResourceDomain] rd on rd.DomainId = d.[Id]
where 
u.Username = @username
and d.[Id] = @domain


END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_ServerSetting_List]    Script Date: 22/04/2021 21:09:58 ******/
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
/****** Object:  StoredProcedure [dbo].[Zesty_Session_Create]    Script Date: 22/04/2021 21:09:58 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:      <Author, , Name>
-- Create Date: <Create Date, , >
-- Description: <Description, , >
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_Session_Create]
(
	@bearer varchar(300),
	@userid uniqueidentifier,
	@sessionid varchar(100)
)
AS
BEGIN
    -- SET NOCOUNT ON added to prevent extra result sets from
    -- interfering with SELECT statements.
    SET NOCOUNT ON

	DELETE FROM [Session] WHERE [Id] = @sessionid;

INSERT INTO [dbo].[Session]
           ([Id]
           ,[Bearer]
           ,[UserId]
           ,[Created]
           ,[Deleted]
           ,[Body])
     VALUES
           (@sessionid
           ,@bearer
           ,@userid
           ,getdate()
           ,NULL
           ,'{}');


END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_Session_Get]    Script Date: 22/04/2021 21:09:58 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:      <Author, , Name>
-- Create Date: <Create Date, , >
-- Description: <Description, , >
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_Session_Get]
(
	@bearer varchar(300)
)
AS
BEGIN
    -- SET NOCOUNT ON added to prevent extra result sets from
    -- interfering with SELECT statements.
    SET NOCOUNT ON

	SELECT [Body] FROM [dbo].[Session] WHERE [Bearer] = @bearer AND [Deleted] IS NULL;

END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_Session_Save]    Script Date: 22/04/2021 21:09:58 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:      <Author, , Name>
-- Create Date: <Create Date, , >
-- Description: <Description, , >
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_Session_Save]
(
	@bearer varchar(300),
	@body varchar(MAX)
)
AS
BEGIN
    -- SET NOCOUNT ON added to prevent extra result sets from
    -- interfering with SELECT statements.
    SET NOCOUNT ON


	UPDATE [dbo].[Session] SET [Body] = @body WHERE [Bearer] = @bearer;
END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_Token_Add]    Script Date: 22/04/2021 21:09:58 ******/
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
/****** Object:  StoredProcedure [dbo].[Zesty_Trace]    Script Date: 22/04/2021 21:09:58 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:      <Author, , Name>
-- Create Date: <Create Date, , >
-- Description: <Description, , >
-- =============================================
CREATE PROCEDURE [dbo].[Zesty_Trace]
(
	@className varchar(200),
	@method varchar(200),
	@hostname varchar(200),
	@clientip varchar(200),
	@sessionid varchar(200),
	@username varchar(200),
	@domain varchar(200),
	@resource varchar(200),
	@message varchar(200),
	@error varchar(200),
	@millis int
)
AS
BEGIN

SET NOCOUNT ON

INSERT INTO [dbo].[Trace]
           ([Created]
           ,[Class]
           ,[Method]
           ,[Hostname]
           ,[ClientIP]
           ,[SessionID]
           ,[Username]
		   ,[Domain]
           ,[Resource]
           ,[Message]
           ,[Error]
           ,[Millis])
     VALUES
           (GETDATE()
           ,@className
           ,@method
           ,@hostname
           ,@clientip
           ,@sessionid
           ,@username
		   ,@domain
           ,@resource
           ,@message
           ,@error
           ,@millis);

END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_Translation_List_ByLanguage]    Script Date: 22/04/2021 21:09:58 ******/
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
/****** Object:  StoredProcedure [dbo].[Zesty_User_Add]    Script Date: 22/04/2021 21:09:58 ******/
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


	@id uniqueidentifier,
	@username varchar(200),
	@email varchar(200),
	@firstname varchar(50),
	@lastname varchar(50)

AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;


INSERT INTO [dbo].[User] ([Id],[Username],[Email],[Firstname],[Lastname],[ResetToken],[Deleted],[Created]) VALUES (@id,@username,@email,@firstname,@lastname,null,null,getdate());



END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_User_AlreadyExists]    Script Date: 22/04/2021 21:09:58 ******/
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

	SELECT * FROM [dbo].[User] WHERE [Username] = @username OR [Email] = @email;

END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_User_Authorize]    Script Date: 22/04/2021 21:09:58 ******/
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
/****** Object:  StoredProcedure [dbo].[Zesty_User_Deauthorize]    Script Date: 22/04/2021 21:09:58 ******/
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
/****** Object:  StoredProcedure [dbo].[Zesty_User_Delete]    Script Date: 22/04/2021 21:09:58 ******/
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

	update [dbo].[user] set [Deleted] = getdate() where [Id] = @userid;


END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_User_Domain]    Script Date: 22/04/2021 21:09:58 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE PROCEDURE [dbo].[Zesty_User_Domain]
(
	@userid uniqueidentifier,
	@domainid uniqueidentifier
)
AS
BEGIN
    -- SET NOCOUNT ON added to prevent extra result sets from
    -- interfering with SELECT statements.
    SET NOCOUNT ON


	UPDATE [User] SET [DomainId] = @domainid WHERE [Id] = @userid;
END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_User_Get]    Script Date: 22/04/2021 21:09:58 ******/
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
	select [Id], [Username], [Email], [Firstname], [Lastname], [Deleted], [Created] from dbo.[user] where [id] = @user;

else
	select [Id], [Username], [Email], [Firstname], [Lastname], [Deleted], [Created] from dbo.[user] where [username] = @user or [email] = @user;

	
END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_User_Get_ByResetToken]    Script Date: 22/04/2021 21:09:58 ******/
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
from dbo.[user] u
where 
u.ResetToken = @token
and u.ResetToken is not null
and datediff(minute, u.ResetTokenCreated, getdate()) < 10
and u.Deleted is null;



END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_User_Get_ByUsername]    Script Date: 22/04/2021 21:09:58 ******/
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
from dbo.[user] u
where 
[username] = @username


END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_User_HardDelete]    Script Date: 22/04/2021 21:09:58 ******/
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
	delete from [dbo].[DashboardWidget] where DashboardId in (select [id] from Dashboard where [userid] = @userid);
	delete from [dbo].[Dashboard] where [userid] = @userid;
	delete from [dbo].[Token] where [userid] = @userid;
	delete from [dbo].[UserPassword] where [userid] = @userid;
	delete from [dbo].[UserProperty]  where [userid] = @userid;
	delete from [dbo].[User] where [id] = @userid;
	DELETE FROM [dbo].[NotificationReaded] WHERE [UserId] = @userid;
END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_User_List]    Script Date: 22/04/2021 21:09:58 ******/
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

	select [Id], [Username], [Email], [Firstname], [Lastname], [Deleted], [Created] from dbo.[user]
END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_User_Update]    Script Date: 22/04/2021 21:09:58 ******/
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


UPDATE dbo.[User] SET
	[Username] = @username,
	[Email] = @email,
	[Firstname] = @firstname,
	[Lastname] = @lastname
WHERE
	[Id] = @userid;


END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_User_Update_ResetToken]    Script Date: 22/04/2021 21:09:58 ******/
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
	declare @id as uniqueidentifier;

	set @token = newid();
	set @id = (select top 1 Id from dbo.[User] WHERE [Email] = @email);

	if @id is null 
		begin
			select convert(uniqueidentifier, '00000000-0000-0000-0000-000000000000');
		end
	else
		begin
			update dbo.[user] set ResetToken = @token, ResetTokenCreated = GETDATE() WHERE [Deleted] is null and [Email] = @email;
			select @token;
		end
END



--exec Zesty_User_Update_ResetToken 'emilianocarlesi@gmail.com'
GO
/****** Object:  StoredProcedure [dbo].[Zesty_UserProperty_Delete]    Script Date: 22/04/2021 21:09:58 ******/
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


	DELETE FROM dbo.[UserProperty] WHERE [UserId] = @userid AND [Key] = @propertyName;

END
GO
/****** Object:  StoredProcedure [dbo].[Zesty_UserProperty_List_ByUserid]    Script Date: 22/04/2021 21:09:58 ******/
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
/****** Object:  StoredProcedure [dbo].[Zesty_UserProperty_Set]    Script Date: 22/04/2021 21:09:58 ******/
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



	IF EXISTS (SELECT * FROM dbo.[UserProperty] WHERE [UserId] = @userid AND [Key] = @propertyName) 
	BEGIN
		UPDATE dbo.[UserProperty] 
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
