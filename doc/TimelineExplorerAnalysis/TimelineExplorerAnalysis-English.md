# Analyzing Hayabusa Results With Timeline Explorer

## About

[Timeline Explorer](https://ericzimmerman.github.io/#!index.md) is a free but closed-source tool to replace Excel when analyzing CSV files for DFIR purposes.
It is a Windows-only GUI tool written in C#.
This tool is great for small investigations by a single analyst and for people just first learning DFIR analysis, however, the interface can be hard to understand at first so please use this guide to understand the different features.

## Table of Contents

- [Analyzing Hayabusa Results With Timeline Explorer](#analyzing-hayabusa-results-with-timeline-explorer)
  - [About](#about)
  - [Table of Contents](#table-of-contents)
  - [Installation and Running](#installation-and-running)
  - [Loading a CSV file](#loading-a-csv-file)
  - [Data Filtering](#data-filtering)
  - [Header Options](#header-options)
    - [Conditional Formatting](#conditional-formatting)
  - [Searching](#searching)
  - [Freezing columns](#freezing-columns)
  - [Dragging column headers to group by](#dragging-column-headers-to-group-by)
  - [Skins](#skins)
  - [Sessions](#sessions)

## Installation and Running

There is no need to install the application.
Just download the latest version from [https://ericzimmerman.github.io/#!index.md](https://ericzimmerman.github.io/#!index.md), unzip it and run `TimelineExplorer.exe`.
If you do not have the appropriate .NET runtime, a message will pop up telling you that you need to install it.
At the time of writing (2025/2/14), the latest version is `2.1.0` which runs on .NET version `9`.

## Loading a CSV file

Just click `File` -> `Open` from the menu to load a CSV file.

You will see something like this:

![First Start](01-TimelineExplorerFirstStart.png)

At the very bottom, you can see the filename, `Total lines` and `Visible lines`.

Besides the columns found in the CSV file, there are two columns on the left added by Timeline Explorer: `Line` and `Tag`.
`Line` shows the line number but is typically not useful for investigations, so you may want to hide this column.
`Tag` lets you put in a checkmark for events that you want to take note of for further analysis later, etc...
Unfortunately, there is no way to add custom tags to events nor write down comments about events as the CSV file is open in read-only mode to prevent data from being overwritten.

## Data Filtering

If you hover your mouse over the top-right part of a header, you will see a black filter icon appear.

![Basic Data Filtering](02-BasicDataFiltering.png)

You can put checkmarks on severity level to first triage the `high` and `crit` (`critical`) alerts.
This filtering is also very useful to filter out noisy alerts by checking everything under `Rule Title` and then un-checking the noisy rules.

As shown below, if you click on `Text Filters`, you can create more advanced filters:

![Advanced Data Filtering](03-AdvancedDataFiltering.png)

Instead of creating filters here though, it is usually easier to click on the `ABC` icon under the header and apply filters here:

![ABC Filtering](04-ABC-Filtering.png)

Unfortunately, these two places provide slightly different filtering options so you should be aware of both places to filter on data.

For example, if you have too many `Proc Exec` events that you would like to filter out, you can choose `Does not contain` and type `Proc Exec` to ignore those events:

![Rule Filtering](05-RuleFiltering.png)

If you look towards the bottom, you can see the rule for the filter in different colors.
If you want to temporarily disable the filter, just uncheck it.
If you want to clear all of the filters, click the `X` button.

If you want to ignore another noisy rule, you should open up the `Filter Editor` by clicking on `Edit Filter` in the bottom-right corner:

![Filter Editor](06-FilterEditor.png)

Copy the `Not Contains([Rule Title], 'Proc Exec')` text, add `and`, paste in the same filter and change `Proc Exec` to `Possible LOLBIN` and now you can ignore these two rules:

![Multiple Filters](07-MultipleFilters.png)

The easiest way to combine multiple filters is by first creating the filter syntax from the `ABC` icon, then copy, paste, and edit that text and combine the filters with `and`, `or` and `not`.

You can also click on any of the colored text to get a dropdown box for the possible options to edit your filters:

![Dropdown editing](08-DropDownEditing.png)

## Header Options

If you right-click on any of the headers, you will get the following options:

![Header Options](09-HeaderOptions.png)

Most of these options are self-explanatory.

* After you hide a column, you can show it again by opening the `Column Chooser`, right-click on the column name and click `Show Column`.
* `Group By This Column` has the same effect as dragging a column header above to group by. (Explained in more detail later.)
* `Hide Group By Box` will just hide the `Drag a column header here to group by that column` text and move the search bar over.

### Conditional Formatting

You can format the text with color, bold font, etc... by clicking `Conditional Formatting` -> `Highlight Cell Rules` -> `Equal To...`:

![Conditional Formatting](10-ConditionalFormatting.png)

For example, if you wanted to show `critical` alerts with `Red Fill`, then just type `crit` and choose `Red Fill` from the options, check `Apply formatting to an entire row` and hit `OK`.

![Crit](11-Crit.png)

Now `critical` alerts will show up in red as shown below:

![Red fill](12-RedFill.png)

You can continue doing this by adding color for the `low`, `medium` and `high` alerts as well.

## Searching

By default, when you type in some text in the search bar, it will perform filtering and only show results that contain the text somewhere in the row.
You can see how many hits you have by checking the `Visible lines` field at the bottom.

You can change this behavior by clicking `Search options` at the very bottom right.
This will show the following:

![Search Options](13-SearchOptions.png)

If you change the `Behavior` from `Filter` to `Search` you can search for text normally.

> Note: It usually takes time to switch the behavior and Timeline Explorer will hang for a bit, so be patient after clicking.

The default `Match criteria` is `Mixed` but can be changed to `Or`, `And`, or `Exact`.
If you change it to anything except `Mixed`, you can then set the `Condition` from `Contains` to `Starts with`, `Like` or `Equals`.

The `Match criteria` of `Mixed` is complicated as it sometimes uses `AND` logic and sometimes `OR` but can be very flexible once learned.
It operates as follows:
* If you separate words by spaces, it will be treated as `OR` logic.
* If you want to include spaces in your search, then you need to add quotes.
* Precede a condition with `+` for `AND` logic.
* Precede a condition with `-` to exclude results.
* Filter on a specific column with the `ColumnName:FilterString` format.
* If you filter on a specific column and also include a separate keyword, it will be `AND` logic.

Examples:
| Search Criteria                  | Description                                                                                                                                     |
|----------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------|
| mimikatz                         | Selects records that contain the `mimikatz` string in any search column.                                                                        |
| one two three                    | Selects records that contain either `one` OR `two` OR `three` in any search column.                                                             |
| "hoge hoge"                      | Selects records that contain `hoge hoge` in any search column.                                                                                  |
| mimikatz +"Bad Guy"              | Selects records that contain both `mimikatz` AND `Bad Guy` in any search column.                                                                |
| EventID:4624 kali                | Selects records that contain `4624` in the column that starts with `EventID` AND contains `kali` in any search column.                          |
| data +entry -mark                | Selects records that contain both `data` AND `entry` in any search column, excluding records that contain `mark`.                               |
| manu mask -file                  | Selects records that contain `menu` OR `mask`, excluding records that contain `file`.                                                           |
| From:Roller Subj:"currency mask" | Selects records that contain `Roller` in the column that starts with `From` AND contains `currency mask` in the column that starts with `Subj`. |
| import -From:Steve               | Selects records that contain `import` in any search column, excluding records that contain `Steve` in the column that starts with `From`.       |

## Freezing columns

While not a search option, you can configure the `First scrollable column` under the `Search options` menu.
Most analysts will set this to `Timestamp` so that they can always see what time certain events happened.

## Dragging column headers to group by

If you drag a column header to the `Drag a column header here to group by that column`, Timeline Explorer will group by that column.
It is common to group by `Level` so that you can prioritize alerts by severity:

![Group by](14-GroupBy.png)

If you have multiple computers in your results, you can further group-by `Computer` to triage based on different severity levels for each computer.

## Skins

You can change the color theme from `Tools` -> `Skins` if you prefer dark mode, etc...

## Sessions

If you customize the columns, appearance, add filters, etc... and you want to save those settings for later, be sure to save your session from `File` -> `Session` -> `Save`.