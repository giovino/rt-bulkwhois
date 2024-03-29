# COPYRIGHT:
#
# Copyright 2009 REN-ISAC[1] and The Trustees of Indiana University[2]
#
# LICENSE:
#
# This work is made available to you under the terms of Version 2 of
# the GNU General Public License.
#
# This work is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301 or visit their web page on the internet at
# http://www.gnu.org/licenses/old-licenses/gpl-2.0.html.
#
# Author wes@barely3am.com (with the help of BestPractical.com)
#
# [1] http://www.ren-isac.net
# [2] http://www.indiana.edu

package RT::Bulkwhois;

our $VERSION = '0.00_01';

use warnings;
use strict;

=head1 NAME

RT::Bulkwhois - a perl module for parsing bulkwhois data into tickets

=head1 SYNOPSIS

=cut
eval "require RT::Bulkwhois_Vendor";
die $@ if ($@ && $@ !~ qr{^Can't locate RT/Bulkwhois_Vendor.pm});
eval "require RT::Bulkwhois_Local";
die $@ if ($@ && $@ !~ qr{^Can't locate RT/Bulkwhois_Local.pm});

1;
