INSERT INTO [dbo].[Authorization] ([UserId],[DomainId],[RoleId]) VALUES
(
    (select [Id] from [User] where [Username] = 'aprestia')
    ,(select [Id] from [Domain] where [Name] = 'Europe')
    ,(select [Id] from [Role] where [Name] = 'Administrators')
);
