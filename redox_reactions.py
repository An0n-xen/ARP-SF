from chemify import *

common = ['H', 'h', 'O', 'o']
common_H = ['H', 'h']
common_O = ['O', 'o']

Chemical_dict = {1: [], 2: [], 3: [], 4: [], 5: [], 6: []}
n_moles_dict = {1: [], 2: [], 3: [], 4: [], 5: [], 6: []}
num_af_el_dict = {1: [], 2: [], 3: [], 4: [], 5: [], 6: []}
final_name_dict = {1: [], 2: [], 3: [], 4: [], 5: [], 6: []}
chem_charges_dict = {1: [], 2: [], 3: [], 4: [], 5: [], 6: []}
post_chem_dict = {1: [], 2: [], 3: [], 4: [], 5: [], 6: []}
Oxidation_num = []
Oxidation_num2 = []


# left half

Iter = 1
for name in range(2):
    # Chemical Name
    for i in range(4):
        # Element makingup Chemical
        Element = input('Element name:')
        n_moles = int(input("Number of moles:"))
        num_af_el = int(input('Number after element:'))

        Chemical_dict[Iter].append(Element)
        n_moles_dict[Iter].append(n_moles)
        num_af_el_dict[Iter].append(num_af_el)

        if num_af_el == 1 or n_moles == 1:
            if num_af_el == 1 and n_moles == 1:
                el_name = chemify_words(Element)
                final_name = '{}'.format(el_name)
                final_name_dict[Iter].append(final_name)

            elif num_af_el == 1:
                el_name = chemify_words(Element)
                final_name = '{}{}'.format(n_moles, el_name)
                final_name_dict[Iter].append(final_name)

            else:
                el_name = chemify_words(Element)
                final_name = '{}{}'.format(el_name, num_af_el)
                final_name_dict[Iter].append(final_name)

        else:
            el_name = chemify_words(Element)
            final_name = '{}{}{}'.format(n_moles, el_name, num_af_el)
            final_name_dict[Iter].append(final_name)

        print('Input next Element')
        print('1 = yes , 0 = no')

        Option = int(input('(1 / 0):'))

        if Option == 1:
            continue
        else:
            break

    chem_charges_dict[Iter].append(int(input('Input charge of chemical:')))

    # Left half
    # Chemical 1

    post_chem_dict[Iter]

    count = 0
    for eat in Chemical_dict[Iter]:

        if eat != 'h' and eat != 'o':
            post_chem_dict[Iter] = count

        count = count + 1

    if any(i in common_H for i in Chemical_dict[Iter]):

        Oxidation_o = -2
        Oxidation_h = 1

        post_h = Chemical_dict[Iter].index('h')

        if any(i in common_O for i in Chemical_dict[Iter]):
            post_o = Chemical_dict[Iter].index('o')
            oxo_chem = -1 * ((num_af_el_dict[Iter][post_h] * Oxidation_h) + (num_af_el_dict[Iter][post_o] * Oxidation_o)) + chem_charges_dict[Iter][0]
            oxo_chem = oxo_chem / num_af_el_dict[Iter][post_chem_dict[Iter]]
            Oxidation_num.append(oxo_chem)

            # Oxo shit
            if oxo_chem > 0:
                print('{} {}{}'.format('Oxidation number =', oxo_chem, '+'))

            else:
                print('{} {}'.format('Oxidation number =', oxo_chem))

        else:
            try:
                oxo_chem = -1 * (n_moles_dict[Iter][post_h] * num_af_el_dict[Iter][post_h] * Oxidation_h) + (chem_charges_dict[Iter][0])
                oxo_chem = oxo_chem / num_af_el_dict[Iter][post_chem_dict[Iter]]
                Oxidation_num.append(oxo_chem)

            except TypeError:
                oxo_chem = chem_charges_dict[Iter][0]
                Oxidation_num.append(oxo_chem)

            # Oxo shit
            if oxo_chem > 0:
                print('{} {}{}'.format('Oxidation number = ', oxo_chem, '+'))

            else:
                print('{} {}'.format('Oxidation number = ', oxo_chem))

    elif any(i in common_O for i in Chemical_dict[Iter]):

        Oxidation_o = -2
        Oxidation_h = 1

        post_o = Chemical_dict[Iter].index('o')

        if any(i in common_H for i in Chemical_dict[Iter]):
            post_h = Chemical_dict[Iter].index('h')
            oxo_chem = -1 * ((num_af_el_dict[Iter][post_o] * Oxidation_o) + (num_af_el_dict[Iter][post_h] * Oxidation_h)) + chem_charges_dict[Iter][0]
            oxo_chem = oxo_chem / num_af_el_dict[Iter][post_chem_dict[Iter]]
            Oxidation_num.append(oxo_chem)

            # Oxo shit
            if oxo_chem > 0:
                print('{} {}{}'.format('Oxidation number =', oxo_chem, '+'))

            else:
                print('{} {}',format('Oxidation number = ', oxo_chem))

        else:
            try:
                oxo_chem = -1 * (n_moles_dict[Iter][post_o] * num_af_el_dict[Iter][post_o] * Oxidation_o) + (chem_charges_dict[Iter][0])
                oxo_chem = oxo_chem / num_af_el_dict[Iter][post_chem_dict[Iter]]
                Oxidation_num.append(oxo_chem)

            except TypeError:
                oxo_chem = chem_charges_dict[Iter][0]
                Oxidation_num.append(oxo_chem)

            # Oxo shit
            if oxo_chem > 0:
                print('{} {}{}'.format('Oxidation number = ', oxo_chem, '+'))

            else:
                print('{} {}'.format('Oxidation number = ', oxo_chem))

    else:
        oxo_chem = chem_charges_dict[Iter][0]
        Oxidation_num.append(oxo_chem)

        # Oxo shit
        if oxo_chem > 0:
            print('{} {}{}'.format('Oxidation number =', oxo_chem, '+'))

        else:
            print('{} {}'.format('Oxidation number = ', oxo_chem))

    Iter = Iter + 1

    print()
    print('{} {}'.format((Iter), 'chemical'))
    print()
    print('YES =1 and NO = 0')
    print()
    option = int(input('Add another Chemical?:'))
    print('YES =1 and NO = 0')

    if option == 1:
        continue

    else:
        break

# Right half
Iter = 4
for name in range(2):
    for i in range(4):
        Element = input('Element name :')
        n_moles = int(input("Number of moles:"))
        num_af_el = int(input('Number after element:'))

        Chemical_dict[Iter].append(Element)
        n_moles_dict[Iter].append(n_moles)
        num_af_el_dict[Iter].append(num_af_el)

        if num_af_el == 1 or n_moles == 1:
            if num_af_el == 1 and n_moles == 1:
                el_name = chemify_words(Element)
                final_name = '{}'.format(el_name)
                final_name_dict[Iter].append(final_name)

            elif num_af_el == 1:
                el_name = chemify_words(Element)
                final_name = '{}{}'.format(n_moles, el_name)
                final_name_dict[Iter].append(final_name)

            else:
                el_name = chemify_words(Element)
                final_name = '{}{}'.format(el_name, num_af_el)
                final_name_dict[Iter].append(final_name)

        else:
            el_name = chemify_words(Element)
            final_name = '{}{}{}'.format(n_moles, el_name, num_af_el)
            final_name_dict[Iter].append(final_name)

        print('Next Element')
        print('1 = yes , 0 = no')

        Option = int(input('(1 / 0):'))

        if Option == 1:
            continue
        else:
            break

    chem_charges_dict[Iter].append(int(input('Input charge of chem:')))

    # Left half
    # Chemical 1

    post_chem_dict[Iter]

    count = 0
    for eat in Chemical_dict[Iter]:

        if eat != 'h' and eat != 'o':
            post_chem_dict[Iter] = count

        count = count + 1

    if any(i in common_H for i in Chemical_dict[Iter]):

        Oxidation_o = -2
        Oxidation_h = 1

        post_h = Chemical_dict[Iter].index('h')

        if any(i in common_O for i in Chemical_dict[Iter]):
            post_o = Chemical_dict[Iter].index('o')
            oxo_chem = -1 * ((num_af_el_dict[Iter][post_h] * Oxidation_h) + (num_af_el_dict[Iter][post_o] * Oxidation_o)) + chem_charges_dict[Iter][0]
            oxo_chem = oxo_chem / num_af_el_dict[Iter][post_chem_dict[Iter]]
            Oxidation_num.append(oxo_chem)

            # Oxo shit
            if oxo_chem > 0:
                print('{} {}{}'.format('Oxidation number = ', oxo_chem, '+'))

            else:
                print('{} {}'.format('Oxidation number = ', oxo_chem))

        else:
            try:
                oxo_chem = -1 * (n_moles_dict[Iter][post_h] * num_af_el_dict[Iter][post_h] * Oxidation_h) + (chem_charges_dict[Iter][0])
                oxo_chem = oxo_chem / num_af_el_dict[Iter][post_chem_dict[Iter]]
                Oxidation_num.append(oxo_chem)

            except TypeError:
                oxo_chem = chem_charges_dict[Iter][0]
                Oxidation_num.append(oxo_chem)

            # Oxo shit
            if oxo_chem > 0:
                print('{} {}{}'.format('Oxidatin number = ', oxo_chem, '+'))

            else:
                print('{} {}'.format('Oxidation number = ', oxo_chem))

    elif any(i in common_O for i in Chemical_dict[Iter]):

        Oxidation_o = -2
        Oxidation_h = 1

        post_o = Chemical_dict[Iter].index('o')

        if any(i in common_H for i in Chemical_dict[Iter]):
            post_h = Chemical_dict[Iter].index('h')
            oxo_chem = -1 * ((num_af_el_dict[Iter][post_o] * Oxidation_o) + (num_af_el_dict[Iter][post_h] * Oxidation_h)) + chem_charges_dict[Iter][0]
            oxo_chem = oxo_chem / num_af_el_dict[Iter][post_chem_dict[Iter]]
            Oxidation_num2.append(oxo_chem)

            # Oxo shit
            if oxo_chem > 0:
                print('{} {}{}'.format('Oxidation number = ', oxo_chem, '+'))

            else:
                print('{} {}'.format('Oxidation number = ', oxo_chem))

        else:
            try:
                oxo_chem = -1 * (n_moles_dict[Iter][post_o] * num_af_el_dict[Iter][post_o] * Oxidation_o) + (chem_charges_dict[Iter][0])
                oxo_chem = oxo_chem / num_af_el_dict[Iter][post_chem_dict[Iter]]
                Oxidation_num2.append(oxo_chem)

            except TypeError:
                oxo_chem = chem_charges_dict[Iter][0]
                Oxidation_num2.append(oxo_chem)

            # Oxo shit
            if oxo_chem > 0:
                print('{} {}{}'.format('Oxidation number = ', oxo_chem, '+'))

            else:
                print('{} {}'.format('Oxidation number', oxo_chem))

    else:
        oxo_chem = chem_charges_dict[Iter][0]
        Oxidation_num2.append(oxo_chem)

        # Oxo shit
        if oxo_chem > 0:
            print('{} {}{}'.format('Oxidation number', oxo_chem, '+'))

        else:
            print('{} {}'.format('Oxidation number = ', oxo_chem))

    Iter = Iter + 1

    print()
    print('{} {}'.format((Iter), 'chemical'))
    print()
    print('YES =1 and NO = 0')
    print()
    option = int(input('Add another Chemical?:'))
    print('YES =1 and NO = 0')

    if option == 1:
        continue

    else:
        break


for i in range(6):
    try:
        if Oxidation_num[i] < Oxidation_num2[i]:
            print('Oxidation half Equation')
            print()

            if 'o' not in Chemical_dict[i + 1] and 'o' not in Chemical_dict[i + 4]:
                print('this yard')
                Oxo_charge = Oxidation_num2[i] - Oxidation_num[i]
                Water = 'H\u2082' + 'O'
                Hydrogen = "H\u00b1+"
                O_water = 1
                H_water = 2
                H_Hydrogen = 1
                Mole_water = 1
                Mole_Hydrogen = 2

                Number_mole1 = num_af_el_dict[i + 1][post_chem_dict[i + 1]] * n_moles_dict[i + 1][post_chem_dict[i + 1]]
                Number_mole2 = num_af_el_dict[i + 4][post_chem_dict[i + 4]] * n_moles_dict[i + 4][post_chem_dict[i + 4]]

                if Number_mole1 != Number_mole2:
                    # Balancing Needed

                    n_moles_dict[i + 1][post_chem_dict[i + 1]] = n_moles_dict[i + 1][post_chem_dict[i + 1]] * num_af_el_dict[i + 4][post_chem_dict[i + 4]]
                    n_moles_dict[i + 4][post_chem_dict[i + 4]] = n_moles_dict[i + 4][post_chem_dict[i + 4]] * num_af_el_dict[i + 1][post_chem_dict[i + 1]]

                    charge1 = n_moles_dict[i + 1][post_chem_dict[i + 1]] * chem_charges_dict[i + 1][0]
                    charge2 = n_moles_dict[i + 4][post_chem_dict[i + 4]] * chem_charges_dict[i + 4][0]
                    e = charge2 - charge1

                    print('{}{} {} {}{}'.format(Number_mole2, final_name_dict[i + 1], '-->', Number_mole1,final_name_dict[i + 4]))
                    print('{}{} {} {}{} {} {}{}'.format(Number_mole2, final_name_dict[i + 1], '-->', Number_mole1, final_name_dict[i + 4], '+', e, 'e'))

                else:
                    # No balancing needed
                    charge1 = n_moles_dict[i + 1][post_chem_dict[i + 1]] * chem_charges_dict[i + 1][0]
                    charge2 = n_moles_dict[i + 4][post_chem_dict[i + 4]] * chem_charges_dict[i + 4][0]
                    e = charge2 - charge1
                    print('{}{} {} {}{} {} {}{}'.format(n_moles_dict[i + 1][post_chem_dict[i + 1]], final_name_dict[i + 1], '-->', n_moles_dict[i + 4][post_chem_dict[i + 4]], final_name_dict[i + 4], '+', e, 'e'))

            elif 'o' not in Chemical_dict[i + 1]:
                print('first element')
                post_o = Chemical_dict[i + 4].index('o')
                O_el = num_af_el_dict[i + 4][post_o]
                Oxo_charge = Oxidation_num2[i] - Oxidation_num[i]
                Water = 'H\u2082' + 'O'
                Hydrogen = "H\u00b1+"
                O_water = 1
                H_water = 2
                H_Hydrogen = 1
                Mole_water = 1
                Mole_Hydrogen = 2

                if num_af_el_dict[i + 1][post_chem_dict[i + 1]] != num_af_el_dict[i + 4][post_chem_dict[i + 4]]:
                    # Balancing Needed

                    n_moles_dict[i + 1][post_chem_dict[i + 1]] = n_moles_dict[i + 1][post_chem_dict[i + 1]] * num_af_el_dict[i + 4][post_chem_dict[i + 4]]
                    n_moles_dict[i + 4][post_chem_dict[i + 4]] = n_moles_dict[i + 4][post_chem_dict[i + 4]] * num_af_el_dict[i + 1][post_chem_dict[i + 1]]
                    print('{}{} {} {}{}'.format(n_moles_dict[i + 1][post_chem_dict[i + 1]], final_name_dict[i + 1], '-->', n_moles_dict[i + 4][post_chem_dict[i + 4]], final_name_dict[i + 4]))

                    if O_el > 1:
                        # Moles of Oxygen not equal those of water
                        Mole_water = O_el * Mole_water
                        Mole_Hydrogen = O_el * Mole_Hydrogen
                        charge1 = n_moles_dict[i + 1][post_chem_dict[i + 1]] * chem_charges_dict[i + 1][0]
                        charge2 = n_moles_dict[i + 4][post_chem_dict[i + 4]] * chem_charges_dict[i + 4][0]
                        e = charge2 - (charge1 + Mole_Hydrogen)
                        print('{}{} {} {}{} {} {}{} {} {}{} {} {}{}'.format(n_moles_dict[i + 1][post_chem_dict[i + 1]], final_name_dict[i + 1], '+', Mole_water, Water, '-->', n_moles_dict[i + 4][post_chem_dict[i + 4]], final_name_dict[i + 4], '+', Mole_Hydrogen, Hydrogen, '+', e, 'e'))

                    else:
                        # Moles of Oxygen equal those of water
                        charge1 = n_moles_dict[i + 1][post_chem_dict[i + 1]] * chem_charges_dict[i + 1][0]
                        charge2 = n_moles_dict[i + 4][post_chem_dict[i + 4]] * chem_charges_dict[i + 4][0]
                        e = charge2 - (charge1 + Mole_Hydrogen)
                        print('{}{} {} {}{} {} {}{} {} {}{} {} {}{}'.format(n_moles_dict[i + 1][post_chem_dict[i + 1]], final_name_dict[i + 1], '+', Mole_water, Water, '-->', n_moles_dict[i + 4][post_chem_dict[i + 4]], final_name_dict[i + 4], '+', Mole_Hydrogen, Hydrogen, '+', e,'e'))

                else:
                    # No balancing needed
                    if O_el > 1:
                        # Moles of Oxygen not equal those of water +
                        Mole_water = O_el * Mole_water
                        Mole_Hydrogen = O_el * Mole_Hydrogen
                        charge1 = n_moles_dict[i + 1][post_chem_dict[i + 1]] * chem_charges_dict[i + 1][0]
                        charge2 = n_moles_dict[i + 4][post_chem_dict[i + 4]] * chem_charges_dict[i + 4][0]
                        e = (charge2 + Mole_Hydrogen) - charge1
                        print('{}{} {} {}{} {} {}{} {} {}{} {} {}{}'.format(n_moles_dict[i + 1][post_chem_dict[i + 1]], final_name_dict[i + 1], '+', Mole_water, Water, '-->', n_moles_dict[i + 4][post_chem_dict[i + 4]],final_name_dict[i + 4], '+', Mole_Hydrogen, Hydrogen, '+', e, 'e'))

                    else:
                        print()

            elif 'o' not in Chemical_dict[i + 4]:
                print('second element')
                post_o = Chemical_dict[i + 1].index('o')
                O_el = num_af_el_dict[i + 1][post_o]
                Oxo_charge = Oxidation_num2[i] - Oxidation_num[i]
                Water = 'H\u2082' + 'O'
                Hydrogen = "H\u2071+"
                O_water = 1
                H_water = 2
                H_Hydrogen = 1
                Mole_water = 1
                Mole_Hydrogen = 2

                if num_af_el_dict[i + 1][post_chem_dict[i + 1]] != num_af_el_dict[i + 4][post_chem_dict[i + 4]]:
                    n_moles_dict[i + 1][post_chem_dict[i + 1]] = n_moles_dict[i + 1][post_chem_dict[i + 1]] * num_af_el_dict[i + 4][post_chem_dict[i + 4]]
                    n_moles_dict[i + 4][post_chem_dict[i + 4]] = n_moles_dict[i + 4][post_chem_dict[i + 4]] * num_af_el_dict[i + 1][post_chem_dict[i + 1]]
                    print('{}{} {} {}{}'.format(n_moles_dict[i + 1][post_chem_dict[i + 1]], final_name_dict[i + 1], '-->', n_moles_dict[i + 4][post_chem_dict[i + 4]], final_name_dict[i + 4]))

                    if O_el > 1:
                        # Moles of Oxygen not equal those of water
                        Mole_water = O_el * Mole_water
                        Mole_Hydrogen = O_el * Mole_Hydrogen
                        charge1 = n_moles_dict[i + 1][post_chem_dict[i + 1]] * chem_charges_dict[i + 1][0]
                        charge2 = n_moles_dict[i + 4][post_chem_dict[i + 4]] * chem_charges_dict[i + 4][0]
                        e = charge2 - (charge1 + Mole_Hydrogen)
                        print('{}{} {} {}{} {} {}{} {} {}{} {} {}{}'.format(n_moles_dict[i + 1][post_chem_dict[i + 1]], final_name_dict[i + 1], '+', Mole_water, Water, '-->', n_moles_dict[i + 4][post_chem_dict[i + 4]], final_name_dict[i + 4], '+', Mole_Hydrogen, Hydrogen, '+', e, 'e'))

                    else:
                        charge1 = n_moles_dict[i + 1][post_chem_dict[i + 1]] * chem_charges_dict[i + 1][0]
                        charge2 = n_moles_dict[i + 4][post_chem_dict[i + 4]] * chem_charges_dict[i + 4][0]
                        e = charge2 - (charge1 + Mole_Hydrogen)
                        print('{}{} {} {}{} {} {}{} {} {}{} {} {}{}'.format(n_moles_dict[i + 1][post_chem_dict[i + 1]], final_name_dict[i + 1], '+', Mole_Hydrogen, Hydrogen, '-->', n_moles_dict[i + 4][post_chem_dict[i + 4]], final_name_dict[i + 4], '+', Mole_water, Water, '+', e,'e'))

                else:
                    print('{}{} {} {}{}'.format(n_moles_dict[i + 1][post_chem_dict[i + 1]], final_name_dict[i + 1], '-->', n_moles_dict[i + 4][post_chem_dict[i + 4]], final_name_dict[i + 4]))

                    if O_el > 1:
                        # Moles of Oxygen not equal those of water
                        Mole_water = O_el * Mole_water
                        Mole_Hydrogen = O_el * Mole_Hydrogen
                        charge1 = n_moles_dict[i + 1][post_chem_dict[i + 1]] * chem_charges_dict[i + 1][0]
                        charge2 = n_moles_dict[i + 4][post_chem_dict[i + 4]] * chem_charges_dict[i + 4][0]
                        e = charge2 - (charge1 + Mole_Hydrogen)
                        print('{}{} {} {}{} {} {}{} {} {}{} {} {}{}'.format(n_moles_dict[i + 1][post_chem_dict[i + 1]],final_name_dict[i + 1], '+', Mole_water, Water, '-->',n_moles_dict[i + 4][post_chem_dict[i + 4]], final_name_dict[i + 4], '+', Mole_Hydrogen,Hydrogen, '+', e, 'e'))

            else:
                print('this yard')
                post_o1 = Chemical_dict[i + 1].index('o')
                post_o2 = Chemical_dict[i + 4].index('o')
                O_el1 = num_af_el_dict[i + 1][post_o1]
                O_el2 = num_af_el_dict[i + 4][post_o2]
                Oxo_charge = Oxidation_num2[i] - Oxidation_num[i]
                Water = 'H\u2082' + 'O'
                Hydrogen = "H\u00b1+"
                O_water = 1
                H_water = 2
                H_Hydrogen = 1
                Mole_water = 1
                Mole_Hydrogen = 2
                Number_mole1 = num_af_el_dict[i + 1][post_chem_dict[i + 1]] * n_moles_dict[i + 1][post_chem_dict[i + 1]]
                Number_mole2 = num_af_el_dict[i + 4][post_chem_dict[i + 4]] * n_moles_dict[i + 4][post_chem_dict[i + 4]]

                if Number_mole1 != Number_mole2:
                    print('{}{} {} {}{}'.format(Number_mole2, final_name_dict[i + 1], '-->', Number_mole1,final_name_dict[i + 4]))
                    O_el1 = O_el1 * Number_mole2
                    O_el2 = O_el2 * Number_mole1

                    if O_el1 > O_el2:
                        Mole_water = O_el1 - O_el2
                        Mole_Hydrogen = Mole_Hydrogen * Mole_water
                        charge1 = n_moles_dict[i + 1][post_chem_dict[i + 1]] * chem_charges_dict[i + 1][0]
                        charge2 = n_moles_dict[i + 4][post_chem_dict[i + 4]] * chem_charges_dict[i + 4][0]
                        e = charge2 - (charge1 + Mole_Hydrogen)
                        print('{}{} {} {}{} {} {}{} {} {}{} {} {}{}'.format(Number_mole2, final_name_dict[i + 1], '+', Mole_Hydrogen, Hydrogen, '+', e, 'e', '-->', Number_mole1, final_name_dict[i + 4], '+', Mole_water, Water))

                    else:
                        Mole_water = O_el2 - O_el1
                        Mole_Hydrogen = Mole_Hydrogen * Mole_water
                        charge1 = n_moles_dict[i + 1][post_chem_dict[i + 1]] * chem_charges_dict[i + 1][0]
                        charge2 = n_moles_dict[i + 4][post_chem_dict[i + 4]] * chem_charges_dict[i + 4][0]
                        e = charge2 - (charge1 + Mole_Hydrogen)
                        print('{}{} {} {}{} {} {}{} {} {}{} {} {}{}'.format(Number_mole2, final_name_dict[i + 1], '+', Mole_water, Water, '-->', Number_mole1,final_name_dict[i + 4], '+', Mole_Hydrogen,Hydrogen, '+', e, 'e'))

                else:
                    if O_el1 > O_el2:
                        Mole_water = O_el1 - O_el2
                        Mole_Hydrogen = Mole_Hydrogen * Mole_water
                        charge1 = n_moles_dict[i + 1][post_chem_dict[i + 1]] * chem_charges_dict[i + 1][0]
                        charge2 = n_moles_dict[i + 4][post_chem_dict[i + 4]] * chem_charges_dict[i + 4][0]
                        e = charge2 - (charge1 + Mole_Hydrogen)
                        print('{}{} {} {}{} {} {}{} {} {}{} {} {}{}'.format(Number_mole2, final_name_dict[i + 1], '+', Mole_Hydrogen, Hydrogen, '+', e, 'e', '-->', Number_mole1, final_name_dict[i + 4], '+', Mole_water, Water))

                    else:
                        Mole_water = O_el2 - O_el1
                        Mole_Hydrogen = Mole_Hydrogen * Mole_water
                        charge1 = n_moles_dict[i + 1][post_chem_dict[i + 1]] * chem_charges_dict[i + 1][0]
                        charge2 = n_moles_dict[i + 4][post_chem_dict[i + 4]] * chem_charges_dict[i + 4][0]
                        e = charge2 - (charge1 + Mole_Hydrogen)
                        print('{}{} {} {}{} {} {}{} {} {}{} {} {}{}'.format(Number_mole2, final_name_dict[i + 1], '+', Mole_water, Water, '-->', Number_mole1, final_name_dict[i + 4], '+', Mole_Hydrogen, Hydrogen, '+', e, 'e'))

        elif Oxidation_num[i] > Oxidation_num2[i]:
            print('Reduction half Equation')
            print()

            if 'o' not in Chemical_dict[i + 1] and 'o' not in Chemical_dict[i + 4]:
                print('this yard')
                Oxo_charge = Oxidation_num2[i] - Oxidation_num[i]
                Water = 'H\u2082' + 'O'
                Hydrogen = "H\u00b1+"
                O_water = 1
                H_water = 2
                H_Hydrogen = 1
                Mole_water = 1
                Mole_Hydrogen = 2

                Number_mole1 = num_af_el_dict[i + 1][post_chem_dict[i + 1]] * n_moles_dict[i + 1][post_chem_dict[i + 1]]
                Number_mole2 = num_af_el_dict[i + 4][post_chem_dict[i + 4]] * n_moles_dict[i + 4][post_chem_dict[i + 4]]

                if Number_mole1 != Number_mole2:
                    # Balancing Needed

                    n_moles_dict[i + 1][post_chem_dict[i + 1]] = n_moles_dict[i + 1][post_chem_dict[i + 1]] * \
                                                                 num_af_el_dict[i + 4][post_chem_dict[i + 4]]
                    n_moles_dict[i + 4][post_chem_dict[i + 4]] = n_moles_dict[i + 4][post_chem_dict[i + 4]] * \
                                                                 num_af_el_dict[i + 1][post_chem_dict[i + 1]]

                    charge1 = n_moles_dict[i + 1][post_chem_dict[i + 1]] * chem_charges_dict[i + 1][0]
                    charge2 = n_moles_dict[i + 4][post_chem_dict[i + 4]] * chem_charges_dict[i + 4][0]
                    e = charge2 - charge1

                    print('{}{} {} {}{}'.format(Number_mole2, final_name_dict[i + 1], '-->', Number_mole1,final_name_dict[i + 4]))
                    print('{}{} {} {}{} {} {}{}'.format(Number_mole2, final_name_dict[i + 1], '+', e, 'e', '-->', Number_mole1, final_name_dict[i + 4]))

                else:
                    # No balancing needed
                    charge1 = n_moles_dict[i + 1][post_chem_dict[i + 1]] * chem_charges_dict[i + 1][0]
                    charge2 = n_moles_dict[i + 4][post_chem_dict[i + 4]] * chem_charges_dict[i + 4][0]
                    e = charge2 - charge1
                    print('{}{} {} {}{} {} {}{}'.format(n_moles_dict[i + 1][post_chem_dict[i + 1]], final_name_dict[i + 1], '+', e, 'e', '-->', n_moles_dict[i + 4][post_chem_dict[i + 4]], final_name_dict[i + 4]))

            elif 'o' not in Chemical_dict[i + 1]:
                print('this yard')
                Oxo_charge = Oxidation_num2[i] - Oxidation_num[i]
                Water = 'H\u2082' + 'O'
                Hydrogen = "H\u00b1+"
                O_water = 1
                H_water = 2
                H_Hydrogen = 1
                Mole_water = 1
                Mole_Hydrogen = 2

                Number_mole1 = num_af_el_dict[i + 1][post_chem_dict[i + 1]] * n_moles_dict[i + 1][post_chem_dict[i + 1]]
                Number_mole2 = num_af_el_dict[i + 4][post_chem_dict[i + 4]] * n_moles_dict[i + 4][post_chem_dict[i + 4]]

                print('first element')
                post_o = Chemical_dict[i + 4].index('o')
                O_el = num_af_el_dict[i + 4][post_o]

                if num_af_el_dict[i + 1][post_chem_dict[i + 1]] != num_af_el_dict[i + 4][post_chem_dict[i + 4]]:
                    # Balancing Needed

                    n_moles_dict[i + 1][post_chem_dict[i + 1]] = n_moles_dict[i + 1][post_chem_dict[i + 1]] * num_af_el_dict[i + 4][post_chem_dict[i + 4]]
                    n_moles_dict[i + 4][post_chem_dict[i + 4]] = n_moles_dict[i + 4][post_chem_dict[i + 4]] * num_af_el_dict[i + 1][post_chem_dict[i + 1]]
                    print('{}{} {} {}{}'.format(n_moles_dict[i + 1][post_chem_dict[i + 1]], final_name_dict[i + 1], '-->', n_moles_dict[i + 4][post_chem_dict[i + 4]], final_name_dict[i + 4]))

                    if O_el > 1:
                        # Moles of Oxygen not equal those of water
                        Mole_water = O_el * Mole_water
                        Mole_Hydrogen = O_el * Mole_Hydrogen
                        charge1 = n_moles_dict[i + 1][post_chem_dict[i + 1]] * chem_charges_dict[i + 1][0]
                        charge2 = n_moles_dict[i + 4][post_chem_dict[i + 4]] * chem_charges_dict[i + 4][0]
                        e = (charge2 + Mole_Hydrogen) - charge1
                        print('{}{} {} {}{} {} {}{} {} {}{} {} {}{}'.format(n_moles_dict[i + 1][post_chem_dict[i + 1]], final_name_dict[i + 1], '+', Mole_water, Water, '+', e, 'e', '-->', n_moles_dict[i + 4][post_chem_dict[i + 4]],final_name_dict[i + 4], '+', Mole_Hydrogen, Hydrogen))

                    else:
                        # Moles of Oxygen equal those of water
                        charge1 = n_moles_dict[i + 1][post_chem_dict[i + 1]] * chem_charges_dict[i + 1][0]
                        charge2 = n_moles_dict[i + 4][post_chem_dict[i + 4]] * chem_charges_dict[i + 4][0]
                        e = (charge2 + Mole_Hydrogen) - charge1
                        print('{}{} {} {}{} {} {}{} {} {}{} {} {}{}'.format(n_moles_dict[i + 1][post_chem_dict[i + 1]],final_name_dict[i + 1], '+', Mole_water, Water, '+', e, 'e', '-->', n_moles_dict[i + 4][post_chem_dict[i + 4]], final_name_dict[i + 4], '+', Mole_Hydrogen, Hydrogen))

                else:
                    # No balancing needed
                    if O_el > 1:
                        # Moles of Oxygen not equal those of water +
                        Mole_water = O_el * Mole_water
                        Mole_Hydrogen = O_el * Mole_Hydrogen
                        charge1 = n_moles_dict[i + 1][post_chem_dict[i + 1]] * chem_charges_dict[i + 1][0]
                        charge2 = n_moles_dict[i + 4][post_chem_dict[i + 4]] * chem_charges_dict[i + 4][0]
                        e = (charge2 + Mole_Hydrogen) - charge1
                        print('{}{} {} {}{} {} {}{} {} {}{} {} {}{}'.format(n_moles_dict[i + 1][post_chem_dict[i + 1]], final_name_dict[i + 1], '+', Mole_water, Water, '-->', n_moles_dict[i + 4][post_chem_dict[i + 4]], final_name_dict[i + 4], '+', Mole_Hydrogen, Hydrogen, '+', e, 'e'))

                    else:
                        print()

            elif 'o' not in Chemical_dict[i + 4]:

                print('second element')

                post_o = Chemical_dict[i + 1].index('o')

                O_el = num_af_el_dict[i + 1][post_o]

                Oxo_charge = Oxidation_num2[i] - Oxidation_num[i]

                Water = 'H\u2082' + 'O'

                Hydrogen = "H\u2071+"

                O_water = 1

                H_water = 2

                H_Hydrogen = 1

                Mole_water = 1

                Mole_Hydrogen = 2

                if num_af_el_dict[i + 1][post_chem_dict[i + 1]] != num_af_el_dict[i + 4][post_chem_dict[i + 4]]:

                    n_moles_dict[i + 1][post_chem_dict[i + 1]] = n_moles_dict[i + 1][post_chem_dict[i + 1]] * num_af_el_dict[i + 4][post_chem_dict[i + 4]]
                    n_moles_dict[i + 4][post_chem_dict[i + 4]] = n_moles_dict[i + 4][post_chem_dict[i + 4]] * num_af_el_dict[i + 1][post_chem_dict[i + 1]]

                    print('{}{} {} {}{}'.format(n_moles_dict[i + 1][post_chem_dict[i + 1]], final_name_dict[i + 1], '-->', n_moles_dict[i + 4][post_chem_dict[i + 4]], final_name_dict[i + 4]))

                    if O_el > 1:

                        # Moles of Oxygen not equal those of water

                        Mole_water = O_el * Mole_water
                        Mole_Hydrogen = O_el * Mole_Hydrogen

                        charge1 = n_moles_dict[i + 1][post_chem_dict[i + 1]] * chem_charges_dict[i + 1][0]
                        charge2 = n_moles_dict[i + 4][post_chem_dict[i + 4]] * chem_charges_dict[i + 4][0]
                        e = charge2 - (charge1 + Mole_Hydrogen)

                        print('{}{} {} {}{} {} {}{} {} {}{} {} {}{}'.format(n_moles_dict[i + 1][post_chem_dict[i + 1]], final_name_dict[i + 1], '+', Mole_Hydrogen, Hydrogen, '+', e, 'e', '-->', n_moles_dict[i + 4][post_chem_dict[i + 4]], final_name_dict[i + 4], '+', Mole_water, Water))

                    else:

                        charge1 = n_moles_dict[i + 1][post_chem_dict[i + 1]] * chem_charges_dict[i + 1][0]
                        charge2 = n_moles_dict[i + 4][post_chem_dict[i + 4]] * chem_charges_dict[i + 4][0]
                        e = charge2 - (charge1 + Mole_Hydrogen)
                        print('{}{} {} {}{} {} {}{} {} {}{} {} {}{}'.format(n_moles_dict[i + 1][post_chem_dict[i + 1]], final_name_dict[i + 1], '+', Mole_Hydrogen, Hydrogen, '+', e, 'e', '-->', n_moles_dict[i + 4][post_chem_dict[i + 4]], final_name_dict[i + 4], '+', Mole_water, Water))

                else:
                    print('{}{} {} {}{}'.format(n_moles_dict[i + 1][post_chem_dict[i + 1]], final_name_dict[i + 1], '-->',n_moles_dict[i + 4][post_chem_dict[i + 4]], final_name_dict[i + 4]))

                    if O_el > 1:
                        # Moles of Oxygen not equal those of water
                        Mole_water = O_el * Mole_water
                        Mole_Hydrogen = O_el * Mole_Hydrogen
                        charge1 = n_moles_dict[i + 1][post_chem_dict[i + 1]] * chem_charges_dict[i + 1][0]
                        charge2 = n_moles_dict[i + 4][post_chem_dict[i + 4]] * chem_charges_dict[i + 4][0]
                        e = charge2 - (charge1 + Mole_Hydrogen)
                        print('{}{} {} {}{} {} {}{} {} {}{} {} {}{}'.format(n_moles_dict[i + 1][post_chem_dict[i + 1]], final_name_dict[i + 1], '+', Mole_Hydrogen, Hydrogen, '+', e, 'e', '-->', n_moles_dict[i + 4][post_chem_dict[i + 4]], final_name_dict[i + 4], '+', Mole_water, Water))

            else:
                print('this yard')
                post_o1 = Chemical_dict[i + 1].index('o')
                post_o2 = Chemical_dict[i + 4].index('o')
                O_el1 = num_af_el_dict[i + 1][post_o1]
                O_el2 = num_af_el_dict[i + 4][post_o2]
                Oxo_charge = Oxidation_num2[i] - Oxidation_num[i]
                Water = 'H\u2082' + 'O'
                Hydrogen = "H\u00b1+"
                O_water = 1
                H_water = 2
                H_Hydrogen = 1
                Mole_water = 1
                Mole_Hydrogen = 2

                Number_mole1 = num_af_el_dict[i + 1][post_chem_dict[i + 1]] * n_moles_dict[i + 1][post_chem_dict[i + 1]]
                Number_mole2 = num_af_el_dict[i + 4][post_chem_dict[i + 4]] * n_moles_dict[i + 4][post_chem_dict[i + 4]]

                if Number_mole1 != Number_mole2:
                    print('{}{} {} {}{}'.format(Number_mole2, final_name_dict[i + 1], '-->', Number_mole1, final_name_dict[i + 4]))
                    O_el1 = O_el1 * Number_mole2
                    O_el2 = O_el2 * Number_mole1

                    if O_el1 > O_el2:
                        Mole_water = O_el1 - O_el2
                        Mole_Hydrogen = Mole_Hydrogen * Mole_water
                        charge1 = n_moles_dict[i + 1][post_chem_dict[i + 1]] * chem_charges_dict[i + 1][0]
                        charge2 = n_moles_dict[i + 4][post_chem_dict[i + 4]] * chem_charges_dict[i + 4][0]
                        e = charge2 - (charge1 + Mole_Hydrogen)
                        print('{}{} {} {}{} {} {}{} {} {}{} {} {}{}'.format(Number_mole2, final_name_dict[i + 1], '+', Mole_Hydrogen, Hydrogen, '+', e, 'e', '-->', Number_mole1, final_name_dict[i + 4],'+', Mole_water, Water))

                    else:
                        Mole_water = O_el2 - O_el1
                        Mole_Hydrogen = Mole_Hydrogen * Mole_water
                        charge1 = n_moles_dict[i + 1][post_chem_dict[i + 1]] * chem_charges_dict[i + 1][0]
                        charge2 = n_moles_dict[i + 4][post_chem_dict[i + 4]] * chem_charges_dict[i + 4][0]
                        e = charge2 - (charge1 + Mole_Hydrogen)
                        print('{}{} {} {}{} {} {}{} {} {}{} {} {}{}'.format(Number_mole2, final_name_dict[i + 1], '+', Mole_water, Water, '-->', Number_mole1, final_name_dict[i + 4], '+', Mole_Hydrogen, Hydrogen,'+', e, 'e'))

                else:
                    if O_el1 > O_el2:
                        Mole_water = O_el1 - O_el2
                        Mole_Hydrogen = Mole_Hydrogen * Mole_water
                        charge1 = n_moles_dict[i + 1][post_chem_dict[i + 1]] * chem_charges_dict[i + 1][0]
                        charge2 = n_moles_dict[i + 4][post_chem_dict[i + 4]] * chem_charges_dict[i + 4][0]
                        e = charge2 - (charge1 + Mole_Hydrogen)
                        print('{}{} {} {}{} {} {}{} {} {}{} {} {}{}'.format(Number_mole2, final_name_dict[i + 1], '+', Mole_Hydrogen, Hydrogen, '+', e, 'e', '-->', Number_mole1, final_name_dict[i + 4], '+', Mole_water, Water))

                    else:
                        Mole_water = O_el2 - O_el1
                        Mole_Hydrogen = Mole_Hydrogen * Mole_water
                        charge1 = n_moles_dict[i + 1][post_chem_dict[i + 1]] * chem_charges_dict[i + 1][0]
                        charge2 = n_moles_dict[i + 4][post_chem_dict[i + 4]] * chem_charges_dict[i + 4][0]
                        e = charge2 - (charge1 + Mole_Hydrogen)
                        print('{}{} {} {}{} {} {}{} {} {}{} {} {}{}'.format(Number_mole2, final_name_dict[i + 1], '+', Mole_water, Water, '-->', Number_mole1, final_name_dict[i + 4], '+', Mole_Hydrogen, Hydrogen, '+', e, 'e'))

        else:
            print('Neutral Elements')

    except IndexError:
        pass