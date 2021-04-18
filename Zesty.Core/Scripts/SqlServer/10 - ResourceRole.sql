﻿/* administrators */
INSERT INTO [dbo].[ResourceRole] ([ResourceId],[RoleId]) VALUES ((select [Id] from [Resource] where [Url] = '/Secured/Hello'), '62ef76b8-e39e-41c7-86dc-4801642dc655');
INSERT INTO [dbo].[ResourceRole] ([ResourceId],[RoleId]) VALUES ((select [Id] from [Resource] where [Url] = '/sample.private.api'), '62ef76b8-e39e-41c7-86dc-4801642dc655');
INSERT INTO [dbo].[ResourceRole] ([ResourceId],[RoleId]) VALUES ((select [Id] from [Resource] where [Url] = '/system.check.api'), '62ef76b8-e39e-41c7-86dc-4801642dc655');
INSERT INTO [dbo].[ResourceRole] ([ResourceId],[RoleId]) VALUES ((select [Id] from [Resource] where [Url] = '/system.token.api'), '62ef76b8-e39e-41c7-86dc-4801642dc655');
INSERT INTO [dbo].[ResourceRole] ([ResourceId],[RoleId]) VALUES ((select [Id] from [Resource] where [Url] = '/system.domains.api'), '62ef76b8-e39e-41c7-86dc-4801642dc655');
INSERT INTO [dbo].[ResourceRole] ([ResourceId],[RoleId]) VALUES ((select [Id] from [Resource] where [Url] = '/system.resources.api'), '62ef76b8-e39e-41c7-86dc-4801642dc655');
INSERT INTO [dbo].[ResourceRole] ([ResourceId],[RoleId]) VALUES ((select [Id] from [Resource] where [Url] = '/system.roles.api'), '62ef76b8-e39e-41c7-86dc-4801642dc655');
INSERT INTO [dbo].[ResourceRole] ([ResourceId],[RoleId]) VALUES ((select [Id] from [Resource] where [Url] = '/system.domain.api'), '62ef76b8-e39e-41c7-86dc-4801642dc655');
INSERT INTO [dbo].[ResourceRole] ([ResourceId],[RoleId]) VALUES ((select [Id] from [Resource] where [Url] = '/system.info.api'), '62ef76b8-e39e-41c7-86dc-4801642dc655');
INSERT INTO [dbo].[ResourceRole] ([ResourceId],[RoleId]) VALUES ((select [Id] from [Resource] where [Url] = '/system.property.api'), '62ef76b8-e39e-41c7-86dc-4801642dc655');
INSERT INTO [dbo].[ResourceRole] ([ResourceId],[RoleId]) VALUES ((select [Id] from [Resource] where [Url] = '/system.admin.user.add.api'), '62ef76b8-e39e-41c7-86dc-4801642dc655');
INSERT INTO [dbo].[ResourceRole] ([ResourceId],[RoleId]) VALUES ((select [Id] from [Resource] where [Url] = '/system.admin.user.delete.api'), '62ef76b8-e39e-41c7-86dc-4801642dc655');
INSERT INTO [dbo].[ResourceRole] ([ResourceId],[RoleId]) VALUES ((select [Id] from [Resource] where [Url] = '/system.admin.user.harddelete.api'), '62ef76b8-e39e-41c7-86dc-4801642dc655');
INSERT INTO [dbo].[ResourceRole] ([ResourceId],[RoleId]) VALUES ((select [Id] from [Resource] where [Url] = '/system.admin.user.list.api'), '62ef76b8-e39e-41c7-86dc-4801642dc655');
INSERT INTO [dbo].[ResourceRole] ([ResourceId],[RoleId]) VALUES ((select [Id] from [Resource] where [Url] = '/system.admin.user.get.api'), '62ef76b8-e39e-41c7-86dc-4801642dc655');
INSERT INTO [dbo].[ResourceRole] ([ResourceId],[RoleId]) VALUES ((select [Id] from [Resource] where [Url] = '/system.admin.user.update.api'), '62ef76b8-e39e-41c7-86dc-4801642dc655');
INSERT INTO [dbo].[ResourceRole] ([ResourceId],[RoleId]) VALUES ((select [Id] from [Resource] where [Url] = '/system.admin.user.authorize.api'), '62ef76b8-e39e-41c7-86dc-4801642dc655');
INSERT INTO [dbo].[ResourceRole] ([ResourceId],[RoleId]) VALUES ((select [Id] from [Resource] where [Url] = '/system.admin.user.deauthorize.api'), '62ef76b8-e39e-41c7-86dc-4801642dc655');
INSERT INTO [dbo].[ResourceRole] ([ResourceId],[RoleId]) VALUES ((select [Id] from [Resource] where [Url] = '/system.admin.role.list.api'), '62ef76b8-e39e-41c7-86dc-4801642dc655');
INSERT INTO [dbo].[ResourceRole] ([ResourceId],[RoleId]) VALUES ((select [Id] from [Resource] where [Url] = '/system.admin.domain.list.api'), '62ef76b8-e39e-41c7-86dc-4801642dc655');
INSERT INTO [dbo].[ResourceRole] ([ResourceId],[RoleId]) VALUES ((select [Id] from [Resource] where [Url] = '/system.admin.domain.add.api'), '62ef76b8-e39e-41c7-86dc-4801642dc655');
INSERT INTO [dbo].[ResourceRole] ([ResourceId],[RoleId]) VALUES ((select [Id] from [Resource] where [Url] = '/system.admin.role.add.api'), '62ef76b8-e39e-41c7-86dc-4801642dc655');
INSERT INTO [dbo].[ResourceRole] ([ResourceId],[RoleId]) VALUES ((select [Id] from [Resource] where [Url] = '/system.admin.resource.list.api'), '62ef76b8-e39e-41c7-86dc-4801642dc655');
INSERT INTO [dbo].[ResourceRole] ([ResourceId],[RoleId]) VALUES ((select [Id] from [Resource] where [Url] = '/system.admin.resource.grants.api'), '62ef76b8-e39e-41c7-86dc-4801642dc655');
INSERT INTO [dbo].[ResourceRole] ([ResourceId],[RoleId]) VALUES ((select [Id] from [Resource] where [Url] = '/system.admin.resource.authorize.api'), '62ef76b8-e39e-41c7-86dc-4801642dc655');
INSERT INTO [dbo].[ResourceRole] ([ResourceId],[RoleId]) VALUES ((select [Id] from [Resource] where [Url] = '/system.admin.resource.deauthorize.api'), '62ef76b8-e39e-41c7-86dc-4801642dc655');
INSERT INTO [dbo].[ResourceRole] ([ResourceId],[RoleId]) VALUES ((select [Id] from [Resource] where [Url] = '/system.admin.resource.add.api'), '62ef76b8-e39e-41c7-86dc-4801642dc655');
INSERT INTO [dbo].[ResourceRole] ([ResourceId],[RoleId]) VALUES ((select [Id] from [Resource] where [Url] = '/system.admin.resource.update.api'), '62ef76b8-e39e-41c7-86dc-4801642dc655');
INSERT INTO [dbo].[ResourceRole] ([ResourceId],[RoleId]) VALUES ((select [Id] from [Resource] where [Url] = '/system.admin.resource.delete.api'), '62ef76b8-e39e-41c7-86dc-4801642dc655');
INSERT INTO [dbo].[ResourceRole] ([ResourceId],[RoleId]) VALUES ((select [Id] from [Resource] where [Url] = '/system.admin.resource.all.api'), '62ef76b8-e39e-41c7-86dc-4801642dc655');

/* users */
INSERT INTO [dbo].[ResourceRole] ([ResourceId],[RoleId]) VALUES ((select [Id] from [Resource] where [Url] = '/Secured/Hello'), '9E73B89C-E645-4084-B925-742818275DF5');
INSERT INTO [dbo].[ResourceRole] ([ResourceId],[RoleId]) VALUES ((select [Id] from [Resource] where [Url] = '/sample.private.api'), '9E73B89C-E645-4084-B925-742818275DF5');
INSERT INTO [dbo].[ResourceRole] ([ResourceId],[RoleId]) VALUES ((select [Id] from [Resource] where [Url] = '/system.check.api'), '9E73B89C-E645-4084-B925-742818275DF5');
INSERT INTO [dbo].[ResourceRole] ([ResourceId],[RoleId]) VALUES ((select [Id] from [Resource] where [Url] = '/system.token.api'), '9E73B89C-E645-4084-B925-742818275DF5');
INSERT INTO [dbo].[ResourceRole] ([ResourceId],[RoleId]) VALUES ((select [Id] from [Resource] where [Url] = '/system.domains.api'), '9E73B89C-E645-4084-B925-742818275DF5');
INSERT INTO [dbo].[ResourceRole] ([ResourceId],[RoleId]) VALUES ((select [Id] from [Resource] where [Url] = '/system.resources.api'), '9E73B89C-E645-4084-B925-742818275DF5');
INSERT INTO [dbo].[ResourceRole] ([ResourceId],[RoleId]) VALUES ((select [Id] from [Resource] where [Url] = '/system.roles.api'), '9E73B89C-E645-4084-B925-742818275DF5');
INSERT INTO [dbo].[ResourceRole] ([ResourceId],[RoleId]) VALUES ((select [Id] from [Resource] where [Url] = '/system.domain.api'), '9E73B89C-E645-4084-B925-742818275DF5');
INSERT INTO [dbo].[ResourceRole] ([ResourceId],[RoleId]) VALUES ((select [Id] from [Resource] where [Url] = '/system.info.api'), '9E73B89C-E645-4084-B925-742818275DF5');
INSERT INTO [dbo].[ResourceRole] ([ResourceId],[RoleId]) VALUES ((select [Id] from [Resource] where [Url] = '/system.property.api'), '9E73B89C-E645-4084-B925-742818275DF5');
