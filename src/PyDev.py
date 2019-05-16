import numpy as np
from numpy.random import rand

# define a Uniform Distribution


def U(MIN, MAX, SAMPLES): return rand(*SAMPLES.shape) * (MAX - MIN) + MIN

# define a Truncated Power Law Distribution


def P(ALPHA, MIN, MAX, SAMPLES): return ((MAX ** (ALPHA+1.) - 1.)
                                         * rand(*SAMPLES.shape) + 1.) ** (1./(ALPHA+1.))

# define an Exponential Distribution


def E(SCALE, SAMPLES): return -SCALE*np.log(rand(*SAMPLES.shape))

class StochasticWalk(object):
    
    def __init__(self, nr_nodes, dimensions, FL_DISTR, VELOCITY_DISTR, WT_DISTR=None, border_policy='reflect'):
        '''
        Base implementation for models with direction uniformly chosen from [0,pi]:
        random_direction, random_walk, truncated_levy_walk
        
        Required arguments:
        
          *nr_nodes*:
            Integer, the number of nodes.
          
          *dimensions*:
            Tuple of Integers, the x and y dimensions of the simulation area.
            
          *FL_DISTR*:
            A function that, given a set of samples, 
             returns another set with the same size of the input set.
            This function should implement the distribution of flight lengths
             to be used in the model.
             
          *VELOCITY_DISTR*:
            A function that, given a set of flight lengths, 
             returns another set with the same size of the input set.
            This function should implement the distribution of velocities
             to be used in the model, as random or as a function of the flight lengths.
          
        keyword arguments:
        
          *WT_DISTR*:
            A function that, given a set of samples, 
             returns another set with the same size of the input set.
            This function should implement the distribution of wait times
             to be used in the node pause.
            If WT_DISTR is 0 or None, there is no pause time.
            
          *border_policy*:
            String, either 'reflect' or 'wrap'. The policy that is used when the node arrives to the border.
            If 'reflect', the node reflects off the border.
            If 'wrap', the node reappears at the opposite edge (as in a torus-shaped area).
        '''
        self.collect_fl_stats = False
        self.collect_wt_stats = False
        self.border_policy = border_policy
        self.dimensions = dimensions
        self.nr_nodes = nr_nodes
        self.FL_DISTR = FL_DISTR
        self.VELOCITY_DISTR = VELOCITY_DISTR
        self.WT_DISTR = WT_DISTR
        
    def __iter__(self):
        def reflect(xy):
            # node bounces on the margins
            for dim, max_d in enumerate(self.dimensions):
                b = np.where(xy[:,dim]<0)[0]
                if b.size > 0:
                    xy[b,dim] = - xy[b,dim]
                    movement[b,dim] = -movement[b,dim]
                b = np.where(xy[:,dim]>max_d)[0]
                if b.size > 0:
                    xy[b,dim] = 2*max_d - xy[b,dim]
                    movement[b,dim] = -movement[b,dim]
        
        def wrap(xy):
            for dim, max_d in enumerate(self.dimensions):
                b = np.where(xy[:,dim]<0)[0]
                if b.size > 0: xy[b,dim] += max_d
                b = np.where(xy[:,dim]>max_d)[0]
                if b.size > 0: xy[b,dim] -= max_d
        
        if self.border_policy == 'reflect':
            borderp = reflect
        elif self.border_policy == 'wrap':
            borderp = wrap
        else:
            borderp = self.border_policy
        
        ndim = len(self.dimensions)
        NODES = np.arange(self.nr_nodes)

        # assign node's positions, flight lengths and velocities
        xy = U(np.zeros(ndim), np.array(self.dimensions), np.dstack((NODES,)*ndim)[0])
        fl = self.FL_DISTR(NODES)
        velocity = self.VELOCITY_DISTR(fl)

        # assign nodes' movements (direction * node velocity)
        direction = U(0., 1., np.zeros((self.nr_nodes, ndim))) - 0.5
        direction /= np.linalg.norm(direction, axis=1)[:, np.newaxis]
        movement = direction * velocity[:, np.newaxis]

        # starts with no wating time
        wt = np.zeros(self.nr_nodes)
        
        if self.collect_fl_stats: self.fl_stats = list(fl)
        if  self.collect_wt_stats: self.wt_stats = list(wt)

        while True:
    
            xy += movement
            fl -= velocity
            
            # step back for nodes that surpassed fl
            arrived = np.where(np.logical_and(velocity>0., fl<=0.))[0]
            if arrived.size > 0:
                diff = fl.take(arrived) / velocity.take(arrived)
                xy[arrived] += np.dstack((diff,)*ndim)[0] * movement[arrived]
            
            # apply border policy
            borderp(xy)
            
            if self.WT_DISTR:
                velocity[arrived] = 0.
                wt[arrived] = self.WT_DISTR(arrived)
                if self.collect_wt_stats: self.wt_stats.extend(wt[arrived])
                # update info for paused nodes
                wt[np.where(velocity==0.)[0]] -= 1.
                arrived = np.where(np.logical_and(velocity==0., wt<0.))[0]
            
            # update info for moving nodes
            if arrived.size > 0:
                
                fl[arrived] = self.FL_DISTR(arrived)
                if self.collect_fl_stats: self.fl_stats.extend(fl[arrived])
                velocity[arrived] = self.VELOCITY_DISTR(fl[arrived])
                v = velocity[arrived]
                direction = U(0., 1., np.zeros((arrived.size, ndim))) - 0.5
                direction /= np.linalg.norm(direction, axis=1)[:, np.newaxis]
                movement[arrived] = v[:, np.newaxis] * direction
    
            yield xy


class RandomWalk(StochasticWalk):

    def __init__(self, nr_nodes, dimensions, velocity=1., distance=1., border_policy='reflect'):
        '''
        Random Walk mobility model.
        This model is based in the Stochastic Walk, but both the flight length and node velocity distributions are in fact constants,
        set to the *distance* and *velocity* parameters. The waiting time is set to None.
        
        Required arguments:
        
          *nr_nodes*:
            Integer, the number of nodes.
          
          *dimensions*: 
            Tuple of Integers, the x and y dimensions of the simulation area.
      
          
        keyword arguments:
        
          *velocity*:
            Double, the value for the constant node velocity. Default is 1.0
          
          *distance*:
            Double, the value for the constant distance traveled in each step. Default is 1.0
            
          *border_policy*:
            String, either 'reflect' or 'wrap'. The policy that is used when the node arrives to the border.
            If 'reflect', the node reflects off the border.
            If 'wrap', the node reappears at the opposite edge (as in a torus-shaped area).
        '''

        if velocity > distance:
            # In this implementation, each step is 1 second,
            # it is not possible to have a velocity larger than the distance
            raise Exception('Velocity must be <= Distance')

        fl = np.zeros(nr_nodes)+distance
        vel = np.zeros(nr_nodes)+velocity

        def FL_DISTR(SAMPLES): return np.array(fl[:len(SAMPLES)])

        def VELOCITY_DISTR(FD): return np.array(vel[:len(FD)])

        StochasticWalk.__init__(
            self, nr_nodes, dimensions, FL_DISTR, VELOCITY_DISTR, border_policy=border_policy)

def stochastic_walk(*args, **kwargs):
    return iter(StochasticWalk(*args, **kwargs))

def random_walk(*args, **kwargs):
    return iter(RandomWalk(*args, **kwargs))

