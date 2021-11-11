# IP-Trust-Manager II

This is a fork of the original Plugin by Andriy Lesyuk. It has been modified by Gero Gothe <gero.gothe [at] medizindoku.de>, as the original ist not working since
DokuWiki/**Hogfather**.

Thus, this software ist also under the GPL-License.

## Additional functionality

You can create a group ```@publicaccess```. If a namespace has ```read```-rights for this group, it can be **publicly accessed by everybody**, whereas the ```@ALL```-group is only meant for logged in users or those accessing the wiki from the defined IPs.

Public access is only granted for those pages, who have ```read```-privileges in the ```@ALL``` group as well, which means: for public access there have to be ```read```-rights in both the ```@ALL``` and the ```@publicaccess``` group.