# -*- coding: utf-8 -*-
#
# Cyrus IMAP documentation build configuration file, created by
# sphinx-quickstart on Fri Jun  6 19:23:19 2014.
#
# This file is execfile()d with the current directory set to its
# containing dir.
#
#
# Note that not all possible configuration values are present in this
# autogenerated file.
#
# All configuration values have a default; values that are commented out
# serve to show the default.

import sys
import os

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#sys.path.insert(0, os.path.abspath('.'))
sys.path.insert(0, os.path.abspath('exts'))

# -- General configuration ------------------------------------------------

# If your documentation needs a minimal Sphinx version, state it here.
needs_sphinx = '1.2'

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    'sphinx.ext.coverage',
    'sphinx.ext.extlinks',
    'sphinx.ext.graphviz',
    'sphinx.ext.ifconfig',
    'sphinx.ext.mathjax',
    'sphinx.ext.todo',
]

extensions.append('sphinxlocal.builders.manpage')
extensions.append('sphinxlocal.roles.cyrusman')

mathjax_path = 'https://cdn.mathjax.org/mathjax/latest/MathJax.js'

todo_include_todos = False

locale_dirs = [ 'locale/' ]
gettext_compact = False

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

# The suffix of source filenames.
source_suffix = '.rst'

# The encoding of source files.
#source_encoding = 'utf-8-sig'

# The master toctree document.
master_doc = 'index'

# General information about the project.
project = u'Cyrus IMAP and SASL'
copyright = u'1993-2016, The Cyrus Team'


# The version info for the project you're documenting, acts as replacement for
# |version| and |release|, also used in various other places throughout the
# built documents.
#
# The short X.Y version.
version = ''
# The full version, including alpha/beta/rc tags.
release = ''

# The language for content autogenerated by Sphinx. Refer to documentation
# for a list of supported languages.
#language = None

# There are two options for replacing |today|: either, you set today to some
# non-false value, then it is used:
#today = ''
# Else, today_fmt is used as the format for a strftime call.
#today_fmt = '%B %d, %Y'

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
exclude_patterns = []

# The reST default role (used for this markup: `text`) to use for all
# documents.
#default_role = None

# If true, '()' will be appended to :func: etc. cross-reference text.
#add_function_parentheses = True

# If true, the current module name will be prepended to all description
# unit titles (such as .. function::).
#add_module_names = True

# If true, sectionauthor and moduleauthor directives will be shown in the
# output. They are ignored by default.
show_authors = True

# The name of the Pygments (syntax highlighting) style to use.
pygments_style = 'sphinx'

# A list of ignored prefixes for module index sorting.
#modindex_common_prefix = []

# If true, keep warnings as "system message" paragraphs in the built documents.
#keep_warnings = False


# -- Options for HTML output ----------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
html_theme = 'cyrus'

# Theme options are theme-specific and customize the look and feel of a theme
# further.  For a list of options available for each theme, see the
# documentation.
#html_theme_options = {}


# Add any paths that contain custom themes here, relative to this directory.
html_theme_path = ["exts/themes"]

# The name for this set of Sphinx documents.  If None, it defaults to
# "<project> v<release> documentation".
#html_title = None

# A shorter title for the navigation bar.  Default is the same as html_title.
#html_short_title = None

# The name of an image file (relative to this directory) to place at the top
# of the sidebar.
#html_logo = "themes/images/logo.gif"

# The name of an image file (within the static path) to use as favicon of the
# docs.  This file should be a Windows icon file (.ico) being 16x16 or 32x32
# pixels large.
html_favicon = "_static/favicon.ico"

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['_static']

# Add any extra paths that contain custom files (such as robots.txt or
# .htaccess) here, relative to this directory. These files are copied
# directly to the root of the documentation.
#html_extra_path = []

# If not '', a 'Last updated on:' timestamp is inserted at every page bottom,
# using the given strftime format.
#html_last_updated_fmt = '%b %d, %Y'

# If true, SmartyPants will be used to convert quotes and dashes to
# typographically correct entities.
#html_use_smartypants = True

# Custom sidebar templates, maps document names to template names.
html_sidebars = {'**' : ['localtoc.html', 'searchbox.html']}

# Additional templates that should be rendered to pages, maps page names to
# template names.
#html_additional_pages = {}

# If false, no module index is generated.
#html_domain_indices = True

# If false, no index is generated.
#html_use_index = True

# If true, the index is split into individual pages for each letter.
#html_split_index = False

# If true, links to the reST sources are added to the pages.
html_show_sourcelink = False

# If true, "Created using Sphinx" is shown in the HTML footer. Default is True.
#html_show_sphinx = True

# If true, "(C) Copyright ..." is shown in the HTML footer. Default is True.
#html_show_copyright = True

# If true, an OpenSearch description file will be output, and all pages will
# contain a <link> tag referring to it.  The value of this option must be the
# base URL from which the finished HTML is served.
#html_use_opensearch = ''

# This is the file name suffix for HTML files (e.g. ".xhtml").
#html_file_suffix = None

# Output file base name for HTML help builder.
htmlhelp_basename = 'Cyrusdoc'


# -- Options for LaTeX output ---------------------------------------------

latex_elements = {
# The paper size ('letterpaper' or 'a4paper').
#'papersize': 'letterpaper',

# The font size ('10pt', '11pt' or '12pt').
#'pointsize': '10pt',

# Additional stuff for the LaTeX preamble.
#'preamble': '',
}

# Grouping the document tree into LaTeX files. List of tuples
# (source start file, target name, title,
#  author, documentclass [howto, manual, or own class]).
latex_documents = [
  ('index', 'Cyrus.tex', u'Cyrus Documentation',
   u'The Cyrus Team', 'manual'),
]

# The name of an image file (relative to this directory) to place at the top of
# the title page.
#latex_logo = None

# For "manual" documents, if this is true, then toplevel headings are parts,
# not chapters.
#latex_use_parts = False

# If true, show page references after internal links.
#latex_show_pagerefs = False

# If true, show URL addresses after external links.
#latex_show_urls = False

# Documents to append as an appendix to all manuals.
#latex_appendices = []

# If false, no module index is generated.
#latex_domain_indices = True

# -- Options for manual page output ---------------------------------------

# One entry per manual page. List of tuples
# (source start file, name, description, authors, manual section).
man_pages = [
        (
            'imap/admin/systemcommands/arbitron',
            'arbitron',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Jeroen van Meeuwen (Kolab Systems)',
                    u'Nic Bernstein (Onlight)'
                ],
            8
    ),

        (
            'imap/admin/systemcommands/backupd',
            'backupd',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                ],
            8
    ),

        (
            'imap/admin/systemcommands/chk_cyrus',
            'chk_cyrus',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Jeroen van Meeuwen (Kolab Systems)',
                    u'Nic Bernstein (Onlight)'
                ],
            8
    ),

        (
            'imap/admin/systemcommands/ctl_backups',
            'ctl_backups',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                ],
            8
    ),

        (
            'imap/admin/systemcommands/ctl_cyrusdb',
            'ctl_cyrusdb',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Jeroen van Meeuwen (Kolab Systems)',
                    u'Nic Bernstein (Onlight)'
                ],
            8
    ),

        (
            'imap/admin/systemcommands/ctl_deliver',
            'ctl_deliver',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Jeroen van Meeuwen (Kolab Systems)',
                    u'Nic Bernstein (Onlight)'
                ],
            8
    ),

        (
            'imap/admin/systemcommands/ctl_mboxlist',
            'ctl_mboxlist',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Jeroen van Meeuwen (Kolab Systems)',
                    u'Nic Bernstein (Onlight)'
                ],
            8
    ),

        (
            'imap/admin/systemcommands/ctl_zoneinfo',
            'ctl_zoneinfo',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Nic Bernstein (Onlight)'
                ],
            8
    ),

        (
            'imap/admin/systemcommands/cvt_cyrusdb',
            'cvt_cyrusdb',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Jeroen van Meeuwen (Kolab Systems)',
                    u'Nic Bernstein (Onlight)'
                ],
            8
    ),

        (
            'imap/admin/systemcommands/cyr_backup',
            'cyr_backup',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                ],
            8
    ),

        (
            'imap/admin/systemcommands/cyr_dbtool',
            'cyr_dbtool',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Jeroen van Meeuwen (Kolab Systems)',
                    u'Nic Bernstein (Onlight)'
                ],
            8
    ),

        (
            'imap/admin/systemcommands/cyr_df',
            'cyr_df',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Jeroen van Meeuwen (Kolab Systems)',
                    u'Nic Bernstein (Onlight)'
                ],
            8
    ),

        (
            'imap/admin/systemcommands/cyr_expire',
            'cyr_expire',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Jeroen van Meeuwen (Kolab Systems)',
                    u'Nic Bernstein (Onlight)'
                ],
            8
    ),

        (
            'imap/admin/systemcommands/cyr_info',
            'cyr_info',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Jeroen van Meeuwen (Kolab Systems)',
                    u'Nic Bernstein (Onlight)'
                ],
            8
    ),

        (
            'imap/admin/systemcommands/cyradm',
            'cyradm',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team'
            ],
            8
    ),

    (
            'imap/admin/systemcommands/cyr_buildinfo',
            'cyr_buildinfo',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                ],
            8
    ),

    (
            'imap/admin/systemcommands/ipurge',
            'ipurge',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Jeroen van Meeuwen (Kolab Systems)',
                    u'Nic Bernstein (Onlight)'
                ],
            8
    ),

        (
            'imap/admin/systemcommands/ptdump',
            'ptdump',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Jeroen van Meeuwen (Kolab Systems)'
                ],
            8
    ),

        (
            'imap/admin/systemcommands/ptexpire',
            'ptexpire',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Jeroen van Meeuwen (Kolab Systems)'
                ],
            8
    ),

        (
            'imap/admin/systemcommands/ptloader',
            'ptloader',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Jeroen van Meeuwen (Kolab Systems)'
                ],
            8
    ),

        (
            'imap/admin/systemcommands/restore',
            'restore',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                ],
            8
    ),

        (
            'imap/admin/systemcommands/unexpunge',
            'unexpunge',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Jeroen van Meeuwen (Kolab Systems)',
                    u'Nic Bernstein (Onlight)'
                ],
            8
    ),

        (
            'imap/admin/systemcommands/squatter',
            'squatter',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Nic Bernstein (Onlight)'
                ],
            8
    ),

        (
            'imap/admin/systemcommands/ctl_conversationsdb',
            'ctl_conversationsdb',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Nic Bernstein (Onlight)'
                ],
            8
    ),

        (
            'imap/admin/systemcommands/sync_client',
            'sync_client',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'David Carter (dpc22@cam.ac.uk)', 
                    u'Ken Murchison (ken@oceana.com)',
                    u'Nic Bernstein (Onlight)'
                ],
            8
    ),

        (
            'imap/admin/systemcommands/cyr_synclog',
            'cyr_synclog',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Nic Bernstein (Onlight)'
                ],
            8
    ),

        (
            'imap/admin/systemcommands/deliver',
            'deliver',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Nic Bernstein (Onlight)'
                ],
            8
    ),

        (
            'imap/admin/systemcommands/cyr_deny',
            'cyr_deny',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Nic Bernstein (Onlight)'
                ],
            8
    ),

        (
            'imap/admin/systemcommands/master',
            'master',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Nic Bernstein (Onlight)'
                ],
            8
    ),

        (
            'imap/admin/systemcommands/mbexamine',
            'mbexamine',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Nic Bernstein (Onlight)'
                ],
            8
    ),

        (
            'imap/admin/systemcommands/mbpath',
            'mbpath',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Nic Bernstein (Onlight)'
                ],
            8
    ),

        (
            'imap/admin/systemcommands/mbtool',
            'mbtool',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Nic Bernstein (Onlight)'
                ],
            8
    ),

        (
            'imap/admin/systemcommands/mkimap',
            'mkimap',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Jeroen van Meeuwen (Kolab Systems)',
                    u'Nic Bernstein (Onlight)'
                ],
            8
    ),

        (
            'imap/admin/systemcommands/quota',
            'quota',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Jeroen van Meeuwen (Kolab Systems)',
                    u'Nic Bernstein (Onlight)'
                ],
            8
    ),

        (
            'imap/admin/systemcommands/reconstruct',
            'reconstruct',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Nic Bernstein (Onlight)'
                ],
            8
    ),

        (
            'imap/admin/systemcommands/fetchnews',
            'fetchnews',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Nic Bernstein (Onlight)'
                ],
            8
    ),

        (
            'imap/admin/systemcommands/fud',
            'fud',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Nic Bernstein (Onlight)'
                ],
            8
    ),

        (
            'imap/admin/systemcommands/httpd',
            'httpd',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Nic Bernstein (Onlight)'
                ],
            8
    ),

        (
            'imap/admin/systemcommands/idled',
            'idled',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Nic Bernstein (Onlight)'
                ],
            8
    ),

        (
            'imap/admin/systemcommands/imapd',
            'imapd',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Nic Bernstein (Onlight)'
                ],
            8
    ),

        (
            'imap/developer/libraries/imclient',
            'imclient',
            u'Cyrus IMAP Libraries Documentation',
            [
                    u'The Cyrus Team',
                    u'Nic Bernstein (Onlight)'
                ],
            3
    ),

        (
            'imap/admin/usercommands/imtest',
            'imtest',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Nic Bernstein (Onlight)'
                ],
            1
    ),

          (
            'imap/admin/usercommands/synctest',
            'synctest',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                ],
            1
    ),

        (
            'imap/admin/usercommands/dav_reconstruct',
            'dav_reconstruct',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                ],
            1
    ),
    
    (
            'imap/admin/usercommands/installsieve',
            'installsieve',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Nic Bernstein (Onlight)'
                ],
            1
    ),

        (
            'imap/admin/usercommands/sieveshell',
            'sieveshell',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team'
            ],
            1
    ),

        (
            'imap/admin/configs/cyrus.conf',
            'cyrus.conf',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Nic Bernstein (Onlight)'
                ],
            5
    ),

        (
            'imap/admin/configs/imapd.conf',
            'imapd.conf',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Nic Bernstein (Onlight)'
                ],
            5
    ),

        (
            'imap/admin/configs/krb.equiv',
            'krb.equiv',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Nic Bernstein (Onlight)'
                ],
            5
    ),

        (
            'imap/admin/systemcommands/lmtpd',
            'lmtpd',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Nic Bernstein (Onlight)'
                ],
            8
    ),

        (
            'imap/admin/systemcommands/lmtpproxyd',
            'lmtpproxyd',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                ],
            8
    ),

    (
            'imap/admin/usercommands/lmtptest',
            'lmtptest',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Nic Bernstein (Onlight)'
                ],
            1
    ),

        (
            'imap/admin/usercommands/mupdatetest',
            'mupdatetest',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Nic Bernstein (Onlight)'
                ],
            1
    ),

        (
            'imap/admin/systemcommands/mupdate',
            'mupdate',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Nic Bernstein (Onlight)'
                ],
            8
    ),

        (
            'imap/admin/systemcommands/nntpd',
            'nntpd',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Nic Bernstein (Onlight)'
                ],
            8
    ),

        (
            'imap/admin/usercommands/nntptest',
            'nntptest',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Nic Bernstein (Onlight)'
                ],
            1
    ),

        (
            'imap/admin/systemcommands/notifyd',
            'notifyd',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Nic Bernstein (Onlight)'
                ],
            8
    ),

        (
            'imap/admin/systemcommands/pop3d',
            'pop3d',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Nic Bernstein (Onlight)'
                ],
            8
    ),

        (
            'imap/admin/systemcommands/pop3proxyd',
            'pop3proxyd',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                ],
            8
    ),

    (
            'imap/admin/usercommands/pop3test',
            'pop3test',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Nic Bernstein (Onlight)'
                ],
            1
    ),

        (
            'imap/admin/systemcommands/rmnews',
            'rmnews',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Nic Bernstein (Onlight)'
                ],
            8
    ),

        (
            'imap/admin/usercommands/sivtest',
            'sivtest',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Nic Bernstein (Onlight)'
                ],
            1
    ),

        (
            'imap/admin/systemcommands/smmapd',
            'smmapd',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Nic Bernstein (Onlight)'
                ],
            8
    ),

        (
            'imap/admin/usercommands/smtptest',
            'smtptest',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Nic Bernstein (Onlight)'
                ],
            1
    ),

        (
            'imap/admin/systemcommands/sync_reset',
            'sync_reset',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'David Carter (dpc22@cam.ac.uk)', 
                    u'Ken Murchison (ken@oceana.com)',
                    u'Nic Bernstein (Onlight)'
                ],
            8
    ),

        (
            'imap/admin/systemcommands/sync_server',
            'sync_server',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'David Carter (dpc22@cam.ac.uk)', 
                    u'Ken Murchison (ken@oceana.com)',
                    u'Nic Bernstein (Onlight)'
                ],
            8
    ),

        (
            'imap/admin/systemcommands/timsieved',
            'timsieved',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'David Carter (dpc22@cam.ac.uk)', 
                    u'Ken Murchison (ken@oceana.com)',
                    u'Nic Bernstein (Onlight)'
                ],
            8
    ),

        (
            'imap/admin/systemcommands/tls_prune',
            'tls_prune',
            u'Cyrus IMAP Documentation',
            [
                    u'The Cyrus Team',
                    u'Nic Bernstein (Onlight)'
                ],
            8
    ),
]

# If true, show URL addresses after external links.
#man_show_urls = False


# -- Options for Texinfo output -------------------------------------------

# Grouping the document tree into Texinfo files. List of tuples
# (source start file, target name, title, author,
#  dir menu entry, description, category)
texinfo_documents = [
  ('index', 'Cyrus', u'Cyrus Documentation',
   u'The Cyrus Team', 'Cyrus', 'One line description of project.',
   'Miscellaneous'),
]

# Documents to append as an appendix to all manuals.
#texinfo_appendices = []

# If false, no module index is generated.
#texinfo_domain_indices = True

# How to display URL addresses: 'footnote', 'no', or 'inline'.
#texinfo_show_urls = 'footnote'

# If true, do not generate a @detailmenu in the "Top" node's menu.
#texinfo_no_detailmenu = False


# -- Options for Epub output ----------------------------------------------

# Bibliographic Dublin Core info.
epub_title = u'Cyrus'
epub_author = u'The Cyrus Team'
epub_publisher = u'The Cyrus Team'
epub_copyright = u'2014, The Cyrus Team'

# The basename for the epub file. It defaults to the project name.
epub_basename = u'Cyrus'

# The HTML theme for the epub output. Since the default themes are not optimized
# for small screen space, using the same theme for HTML and epub output is
# usually not wise. This defaults to 'epub', a theme designed to save visual
# space.
#epub_theme = 'epub'

# The language of the text. It defaults to the language option
# or en if the language is not set.
#epub_language = ''

# The scheme of the identifier. Typical schemes are ISBN or URL.
#epub_scheme = ''

# The unique identifier of the text. This can be a ISBN number
# or the project homepage.
#epub_identifier = ''

# A unique identification for the text.
#epub_uid = ''

# A tuple containing the cover image and cover page html template filenames.
#epub_cover = ()

# A sequence of (type, uri, title) tuples for the guide element of content.opf.
#epub_guide = ()

# HTML files that should be inserted before the pages created by sphinx.
# The format is a list of tuples containing the path and title.
#epub_pre_files = []

# HTML files shat should be inserted after the pages created by sphinx.
# The format is a list of tuples containing the path and title.
#epub_post_files = []

# A list of files that should not be packed into the epub file.
epub_exclude_files = ['search.html']

# The depth of the table of contents in toc.ncx.
#epub_tocdepth = 3

# Allow duplicate toc entries.
#epub_tocdup = True

# Choose between 'default' and 'includehidden'.
#epub_tocscope = 'default'

# Fix unsupported image types using the PIL.
#epub_fix_images = False

# Scale large images.
#epub_max_image_width = 0

# How to display URL addresses: 'footnote', 'no', or 'inline'.
#epub_show_urls = 'inline'

# If false, no index is generated.
#epub_use_index = True

rst_prolog = """
.. |imap_last_stable_version| replace:: 2.4.18
.. |imap_last_stable_branch| replace:: `cyrus-imapd-2.4`
.. |imap_last_stable_next_version| replace:: 2.4.18 + patches
.. |imap_current_stable_version| replace:: 2.5.8
.. |imap_current_stable_next_version| replace:: 2.5.8 + patches
.. |imap_current_stable_branch| replace:: `cyrus-imapd-2.5`
.. |imap_latest_development_version| replace:: 3.0.0-beta3
.. |imap_latest_development_branch| replace:: master
.. |imap_tikanga_stock_version| replace:: 2.3.7
.. |imap_santiago_stock_version| replace:: 2.3.16
.. |imap_maipo_stock_version| replace:: 2.4.17
.. |imap_precise_stock_version| replace:: 2.4.12-2
.. |imap_trusty_stock_version| replace:: 2.4.17+caldav~beta9-3
.. |imap_utopic_stock_version| replace:: 2.4.17+caldav~beta10-5
.. |imap_vivid_stock_version| replace:: 2.4.17+caldav~beta10-17
.. |imap_wily_stock_version| replace:: 2.4.17+caldav~beta10-17
.. |sasl_current_stable_version| replace:: 2.1.26
.. |imap_stable_release_notes| raw:: html

    <a href="2.5/x/2.5.8.html">2.5.8</a>
    
.. |imap_development_release_notes| raw:: html

    <a href="3.0/x/3.0.0-beta3.html">3.0.0-beta3</a>
    
"""

rst_prolog += """
.. |git_cyrus_imapd_url| replace:: https://github.com/cyrusimap/cyrus-imapd.git
"""

# The version in which compatibility support for RFC 2086 (the 'c' and
# 'd' rights) is dropped.
rst_prolog += """
.. |imap_version_rfc2086_dropped| replace:: 3.0
"""

# The version in which the altnamespace setting default changes (was
# off).
rst_prolog += """
.. |imap_version_altnamespace_default_on| replace:: 3.0
"""

# The version in which the unixhierarchysep setting default changes (was
# off).
rst_prolog += """
.. |imap_version_unixhierarchysep_default_on| replace:: 3.0
"""

# The version in which the master process was renamed to cyrus-master.
# Except the rename never happened, so removing this for now as it's just confusing.
## rst_prolog += """
## .. |imap_version_master_renamed| replace:: 3.0
## """

# Bloilerplate configuration file texts.
rst_prolog += """
.. |default-conf-text| replace:: reads its configuration options out of the :cyrusman:`imapd.conf(5)` file unless specified otherwise by **-C**.
.. |cli-dash-c-text| replace:: Use the specified configuration file *config-file* rather than the default :cyrusman:`imapd.conf(5)`.
.. |def-confdir-text| replace:: The *configdirectory* option in :cyrusman:`imapd.conf(5)` is used to determine the default location of the
"""

# New feature version disclaimer for 3.0 (big changes)
rst_prolog += """
.. |v3-new-feature| replace:: This feature was introduced in version 3.0.
.. |v3-new-command| replace:: This command was introduced in version 3.0.
"""

rst_prolog += """
.. |AMS| replace:: :abbr:`AMS (Andrew Mail System)`
.. |CMU| replace:: :abbr:`CMU (Carnegie Mellon University)`
"""

# Uncomment this if you publish to, like, www.cyrusimap.org/~vanmeeuwen/
#rst_prolog += """
#.. WARNING::

    #You are looking at documentation that is maintained by interval.

    #Please see https://www.cyrusimap.org/ for better maintained
    #documentation.
#"""

# Use this as :task:`18`
extlinks = {
        'rfc':('http://tools.ietf.org/html/rfc%s', 'RFC '),
        'task':('https://git.cyrus.foundation/T%s', 'Task #'),
        'issue':('https://github.com/cyrusimap/cyrus-imapd/issues/%s', 'Issue #'),
    }

# Change this to whatever your output root is
# If you're in a local build environment, this might be file://cyrus-imapd/doc/build/imap/admin/$num/$topic/$topic.html    
cyrus_man_url_regex = "http://www.cyrusimap.org/imap/admin/$num/$topic.html";
