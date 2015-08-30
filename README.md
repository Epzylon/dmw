DMW 1.0
===
Abstract:
	The goal of DMW (Do my work) is to avoid to do my work! :P
	Just customize a server (linux RedHat or SuSE) with a few variables

Do my work
############# HOW TO USE ############
- To use this script you have to create a template file
where the variables used for the configuration are stored.
You have a template sample on the repo of the script.
- Once having the template you must upload the template
to the server with the name 'template' and the script
with the name you want, but on the same dir where the template
was uploaded.
- Finally you can run:
. script-name.sh
This will load the template variables and the functions defined 
on the script.
- Once loaded you can run the differente functions defined as commands
or run the 'main' function that will perform all the tasks.


############# TODO ############
- Atomic functions (divide large functions in smallers)
- Add tools installations
- Add package installations
- Manifest (print the current state of config)
- Install HPSA
- Align output
- Clear interface naming for cloned vms



