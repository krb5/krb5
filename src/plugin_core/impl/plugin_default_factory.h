/*
 * plugin_default_factory.h
 *
 */

#ifndef PLUGIN_DEFAULT_FACTORY_H_
#define PLUGIN_DEFAULT_FACTORY_H_

#include <plugin_factory.h>
#include "plugin_pwd_qlty_krb_impl.h"
#include "plugin_pwd_qlty_X_impl.h"


factory_handle plugin_default_factory_get_instance(void);


#endif /* PLUGIN_DEFAULT_FACTORY_H_ */
