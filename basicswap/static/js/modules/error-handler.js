const ErrorHandler = (function() {
    const config = {
        logErrors: true,
        throwErrors: false,
        errorCallbacks: []
    };

    function formatError(error, context) {
        const timestamp = new Date().toISOString();
        const contextStr = context ? ` [${context}]` : '';
        
        if (error instanceof Error) {
            return `${timestamp}${contextStr} ${error.name}: ${error.message}`;
        }
        
        return `${timestamp}${contextStr} ${String(error)}`;
    }

    function notifyCallbacks(error, context) {
        config.errorCallbacks.forEach(callback => {
            try {
                callback(error, context);
            } catch (e) {
                console.error('[ErrorHandler] Error in callback:', e);
            }
        });
    }

    return {
        configure: function(options = {}) {
            Object.assign(config, options);
            return this;
        },

        addCallback: function(callback) {
            if (typeof callback === 'function') {
                config.errorCallbacks.push(callback);
            }
            return this;
        },

        removeCallback: function(callback) {
            const index = config.errorCallbacks.indexOf(callback);
            if (index > -1) {
                config.errorCallbacks.splice(index, 1);
            }
            return this;
        },

        safeExecute: function(fn, context = null, fallbackValue = null) {
            try {
                return fn();
            } catch (error) {
                if (config.logErrors) {
                    console.error(formatError(error, context));
                }
                
                notifyCallbacks(error, context);
                
                if (config.throwErrors) {
                    throw error;
                }
                
                return fallbackValue;
            }
        },

        safeExecuteAsync: async function(fn, context = null, fallbackValue = null) {
            try {
                return await fn();
            } catch (error) {
                if (config.logErrors) {
                    console.error(formatError(error, context));
                }
                
                notifyCallbacks(error, context);
                
                if (config.throwErrors) {
                    throw error;
                }
                
                return fallbackValue;
            }
        },

        wrap: function(fn, context = null, fallbackValue = null) {
            return (...args) => {
                try {
                    return fn(...args);
                } catch (error) {
                    if (config.logErrors) {
                        console.error(formatError(error, context));
                    }
                    
                    notifyCallbacks(error, context);
                    
                    if (config.throwErrors) {
                        throw error;
                    }
                    
                    return fallbackValue;
                }
            };
        },

        wrapAsync: function(fn, context = null, fallbackValue = null) {
            return async (...args) => {
                try {
                    return await fn(...args);
                } catch (error) {
                    if (config.logErrors) {
                        console.error(formatError(error, context));
                    }
                    
                    notifyCallbacks(error, context);
                    
                    if (config.throwErrors) {
                        throw error;
                    }
                    
                    return fallbackValue;
                }
            };
        },

        handleError: function(error, context = null, fallbackValue = null) {
            if (config.logErrors) {
                console.error(formatError(error, context));
            }
            
            notifyCallbacks(error, context);
            
            if (config.throwErrors) {
                throw error;
            }
            
            return fallbackValue;
        },

        try: function(fn, catchFn = null, finallyFn = null) {
            try {
                return fn();
            } catch (error) {
                if (config.logErrors) {
                    console.error(formatError(error, 'ErrorHandler.try'));
                }
                
                notifyCallbacks(error, 'ErrorHandler.try');
                
                if (catchFn) {
                    return catchFn(error);
                }
                
                if (config.throwErrors) {
                    throw error;
                }
                
                return null;
            } finally {
                if (finallyFn) {
                    finallyFn();
                }
            }
        },

        tryAsync: async function(fn, catchFn = null, finallyFn = null) {
            try {
                return await fn();
            } catch (error) {
                if (config.logErrors) {
                    console.error(formatError(error, 'ErrorHandler.tryAsync'));
                }
                
                notifyCallbacks(error, 'ErrorHandler.tryAsync');
                
                if (catchFn) {
                    return await catchFn(error);
                }
                
                if (config.throwErrors) {
                    throw error;
                }
                
                return null;
            } finally {
                if (finallyFn) {
                    await finallyFn();
                }
            }
        },

        createBoundary: function(context) {
            return {
                execute: (fn, fallbackValue = null) => {
                    return ErrorHandler.safeExecute(fn, context, fallbackValue);
                },
                executeAsync: (fn, fallbackValue = null) => {
                    return ErrorHandler.safeExecuteAsync(fn, context, fallbackValue);
                },
                wrap: (fn, fallbackValue = null) => {
                    return ErrorHandler.wrap(fn, context, fallbackValue);
                },
                wrapAsync: (fn, fallbackValue = null) => {
                    return ErrorHandler.wrapAsync(fn, context, fallbackValue);
                }
            };
        }
    };
})();

if (typeof window !== 'undefined') {
    window.ErrorHandler = ErrorHandler;
}

console.log('ErrorHandler module loaded');
